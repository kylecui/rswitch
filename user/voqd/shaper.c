// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "shaper.h"

#define NSEC_PER_SEC 1000000000ULL

static uint64_t clamp_tokens(uint64_t tokens, uint64_t burst)
{
	if (tokens > burst) {
		return burst;
	}
	return tokens;
}

void rs_shaper_init(struct rs_shaper *shaper, uint64_t now_ns)
{
	if (!shaper) {
		return;
	}

	memset(shaper, 0, sizeof(*shaper));
	shaper->last_refill_ns = now_ns;
}

void rs_shaper_configure(struct rs_shaper *shaper, uint64_t rate_bps, uint64_t burst_bytes, int enabled, uint64_t now_ns)
{
	if (!shaper) {
		return;
	}

	shaper->rate_bps = rate_bps;
	shaper->burst_bytes = burst_bytes;
	shaper->enabled = enabled ? 1 : 0;
	shaper->last_refill_ns = now_ns;

	if (!shaper->enabled || shaper->rate_bps == 0 || shaper->burst_bytes == 0) {
		shaper->enabled = 0;
		shaper->tokens = 0;
		return;
	}

	shaper->tokens = shaper->burst_bytes;
}

void rs_shaper_refill(struct rs_shaper *shaper, uint64_t now_ns)
{
	uint64_t elapsed_ns;
	uint64_t add_tokens;

	if (!shaper || !shaper->enabled) {
		return;
	}

	if (now_ns <= shaper->last_refill_ns) {
		return;
	}

	elapsed_ns = now_ns - shaper->last_refill_ns;
	add_tokens = (shaper->rate_bps * elapsed_ns) / (8ULL * NSEC_PER_SEC);

	if (add_tokens > 0) {
		shaper->tokens = clamp_tokens(shaper->tokens + add_tokens, shaper->burst_bytes);
		shaper->last_refill_ns = now_ns;
	}
}

int rs_shaper_admit(struct rs_shaper *shaper, uint32_t pkt_len, uint64_t now_ns)
{
	if (!shaper || !shaper->enabled) {
		return 1;
	}

	rs_shaper_refill(shaper, now_ns);

	if (shaper->tokens < pkt_len) {
		uint64_t missing = pkt_len - shaper->tokens;
		uint64_t wait_ns = (missing * 8ULL * NSEC_PER_SEC) / (shaper->rate_bps ? shaper->rate_bps : 1ULL);
		shaper->delay_ns_total += wait_ns;
		return 0;
	}

	shaper->tokens -= pkt_len;
	shaper->shaped_packets++;
	shaper->shaped_bytes += pkt_len;
	return 1;
}

void rs_shaper_stats(const struct rs_shaper *shaper, struct rs_shaper_stats *stats)
{
	if (!shaper || !stats) {
		return;
	}

	stats->shaped_packets = shaper->shaped_packets;
	stats->shaped_bytes = shaper->shaped_bytes;
	stats->delay_ns_total = shaper->delay_ns_total;
	stats->tokens = shaper->tokens;
	stats->rate_bps = shaper->rate_bps;
	stats->burst_bytes = shaper->burst_bytes;
	stats->enabled = shaper->enabled;
}

void rs_wfq_init(struct rs_wfq_scheduler *sched, int num_queues)
{
	int i;

	if (!sched) {
		return;
	}

	memset(sched, 0, sizeof(*sched));
	if (num_queues < 0) {
		num_queues = 0;
	}
	if (num_queues > RS_SHAPER_WFQ_MAX_QUEUES) {
		num_queues = RS_SHAPER_WFQ_MAX_QUEUES;
	}
	sched->num_queues = num_queues;
	for (i = 0; i < sched->num_queues; i++) {
		sched->queue_weights[i] = 1;
	}
}

void rs_wfq_set_weights(struct rs_wfq_scheduler *sched, const uint32_t *weights, int num_queues)
{
	int i;
	int enabled = 0;

	if (!sched) {
		return;
	}

	if (num_queues < 0) {
		num_queues = 0;
	}
	if (num_queues > RS_SHAPER_WFQ_MAX_QUEUES) {
		num_queues = RS_SHAPER_WFQ_MAX_QUEUES;
	}
	sched->num_queues = num_queues;

	for (i = 0; i < sched->num_queues; i++) {
		uint32_t w = (weights && weights[i] > 0) ? weights[i] : 1;
		sched->queue_weights[i] = w;
		if (w > 0) {
			enabled = 1;
		}
	}

	sched->enabled = enabled;
}

int rs_wfq_select_queue(struct rs_wfq_scheduler *sched, const uint32_t *queue_depths, int num_queues)
{
	int i;
	int selected = -1;
	uint64_t min_vt = ULLONG_MAX;

	if (!sched || !queue_depths || num_queues <= 0) {
		return -1;
	}

	if (num_queues > sched->num_queues) {
		num_queues = sched->num_queues;
	}
	if (num_queues > RS_SHAPER_WFQ_MAX_QUEUES) {
		num_queues = RS_SHAPER_WFQ_MAX_QUEUES;
	}

	for (i = 0; i < num_queues; i++) {
		if (queue_depths[i] == 0 || sched->queue_weights[i] == 0) {
			continue;
		}
		if (sched->virtual_time[i] < min_vt) {
			min_vt = sched->virtual_time[i];
			selected = i;
		}
	}

	if (selected < 0) {
		return -1;
	}

	sched->virtual_time[selected] += (1000000ULL / sched->queue_weights[selected]);
	return selected;
}

int rs_shaper_shared_open(struct rs_shaper_shared_cfg **cfg, int create_if_missing)
{
	int fd;
	int flags;
	void *addr;

	if (!cfg) {
		return -EINVAL;
	}

	flags = O_RDWR;
	if (create_if_missing) {
		flags |= O_CREAT;
	}

	fd = shm_open(RS_SHAPER_SHM_PATH, flags, 0660);
	if (fd < 0) {
		RS_LOG_ERROR("shm_open(%s) failed: %s", RS_SHAPER_SHM_PATH, strerror(errno));
		return -errno;
	}

	if (create_if_missing) {
		if (ftruncate(fd, sizeof(struct rs_shaper_shared_cfg)) < 0) {
			int err = errno;
			close(fd);
			RS_LOG_ERROR("ftruncate shaper shm failed: %s", strerror(err));
			return -err;
		}
	}

	addr = mmap(NULL, sizeof(struct rs_shaper_shared_cfg), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		RS_LOG_ERROR("mmap shaper shm failed: %s", strerror(errno));
		return -errno;
	}

	*cfg = addr;

	if (create_if_missing && (*cfg)->version != RS_SHAPER_CFG_VERSION) {
		memset(*cfg, 0, sizeof(struct rs_shaper_shared_cfg));
		(*cfg)->version = RS_SHAPER_CFG_VERSION;
		(*cfg)->num_ports = RS_SHAPER_MAX_PORTS;
		(*cfg)->generation = 1;
	}

	return 0;
}

void rs_shaper_shared_close(struct rs_shaper_shared_cfg *cfg)
{
	if (!cfg) {
		return;
	}

	if (munmap(cfg, sizeof(struct rs_shaper_shared_cfg)) < 0) {
		RS_LOG_WARN("munmap shaper shm failed: %s", strerror(errno));
	}
}
