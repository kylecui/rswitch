// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <limits.h>

#include "controller.h"

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

struct controller_agent {
    int fd;
    int active;
    int registered;
    struct rs_agent_info info;
    char hostname[64];
    time_t last_seen;
    time_t last_status_req;
};

static volatile sig_atomic_t g_running = 1;

static void controller_signal_handler(int signo)
{
    (void)signo;
    g_running = 0;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const char *ptr = (const char *)buf;

    while (len > 0) {
        ssize_t n = send(fd, ptr, len, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0)
            return -1;

        ptr += (size_t)n;
        len -= (size_t)n;
    }

    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    char *ptr = (char *)buf;

    while (len > 0) {
        ssize_t n = recv(fd, ptr, len, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0)
            return -1;

        ptr += (size_t)n;
        len -= (size_t)n;
    }

    return 0;
}

static int send_msg(int fd, uint8_t type, const void *payload, uint16_t payload_len)
{
    struct rs_ctrl_msg hdr;

    hdr.version = CONTROLLER_PROTO_VERSION;
    hdr.type = type;
    hdr.length = htons(payload_len);

    if (send_all(fd, &hdr, sizeof(hdr)) != 0)
        return -1;

    if (payload_len > 0 && payload) {
        if (send_all(fd, payload, payload_len) != 0)
            return -1;
    }

    return 0;
}

static int recv_msg(int fd, struct rs_ctrl_msg *hdr, char **payload)
{
    uint16_t payload_len;

    if (recv_all(fd, hdr, sizeof(*hdr)) != 0)
        return -1;

    if (hdr->version != CONTROLLER_PROTO_VERSION)
        return -1;

    payload_len = ntohs(hdr->length);
    hdr->length = payload_len;

    if (payload_len == 0) {
        *payload = NULL;
        return 0;
    }

    *payload = malloc(payload_len);
    if (!*payload)
        return -1;

    if (recv_all(fd, *payload, payload_len) != 0) {
        free(*payload);
        *payload = NULL;
        return -1;
    }

    return 0;
}

static void close_agent_slot(struct controller_agent *agent)
{
    if (!agent->active)
        return;

    RS_LOG_INFO("agent disconnected host=%s fd=%d", agent->hostname[0] ? agent->hostname : "<unknown>", agent->fd);
    close(agent->fd);
    memset(agent, 0, sizeof(*agent));
    agent->fd = -1;
}

static int read_file_to_buf(const char *path, char **buf, uint16_t *len)
{
    FILE *fp;
    long fsize;
    size_t nread;
    char *tmp;

    if (!path || !buf || !len)
        return -EINVAL;

    fp = fopen(path, "rb");
    if (!fp)
        return -errno;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -EIO;
    }

    fsize = ftell(fp);
    if (fsize < 0 || fsize > 65535) {
        fclose(fp);
        return -EFBIG;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -EIO;
    }

    tmp = malloc((size_t)fsize);
    if (!tmp && fsize > 0) {
        fclose(fp);
        return -ENOMEM;
    }

    nread = fread(tmp, 1, (size_t)fsize, fp);
    fclose(fp);

    if (nread != (size_t)fsize) {
        free(tmp);
        return -EIO;
    }

    *buf = tmp;
    *len = (uint16_t)fsize;
    return 0;
}

static void send_error_msg(int fd, const char *msg)
{
    uint16_t len = 0;

    if (msg)
        len = (uint16_t)strnlen(msg, 65535);

    if (send_msg(fd, MSG_ERROR, msg, len) != 0)
        RS_LOG_WARN("failed to send MSG_ERROR");
}

static void maybe_drop_stale_agents(struct controller_agent *agents)
{
    time_t now = time(NULL);

    for (int i = 0; i < CONTROLLER_MAX_AGENTS; i++) {
        time_t elapsed;
        int misses;

        if (!agents[i].active || !agents[i].registered)
            continue;

        elapsed = now - agents[i].last_seen;
        if (elapsed < CONTROLLER_HEARTBEAT_SEC)
            continue;

        misses = (int)(elapsed / CONTROLLER_HEARTBEAT_SEC);
        if (misses >= 3) {
            RS_LOG_WARN("agent timeout host=%s misses=%d", agents[i].hostname, misses);
            close_agent_slot(&agents[i]);
        }
    }
}

static void handle_register(struct controller_agent *agent, const char *payload, uint16_t len)
{
    struct rs_agent_info info;

    if (len < sizeof(info)) {
        RS_LOG_WARN("invalid MSG_REGISTER payload len=%u", (unsigned)len);
        send_error_msg(agent->fd, "invalid register payload");
        return;
    }

    memcpy(&info, payload, sizeof(info));
    info.hostname[sizeof(info.hostname) - 1] = '\0';
    info.version[sizeof(info.version) - 1] = '\0';
    info.num_modules = ntohl(info.num_modules);
    info.uptime_sec = ntohl(info.uptime_sec);

    agent->info = info;
    agent->registered = 1;
    agent->last_seen = time(NULL);
    agent->last_status_req = 0;
    snprintf(agent->hostname, sizeof(agent->hostname), "%s", info.hostname[0] ? info.hostname : "unknown");

    RS_LOG_INFO("agent registered host=%s version=%s modules=%u uptime=%u", agent->hostname,
                agent->info.version, agent->info.num_modules, agent->info.uptime_sec);

    if (send_msg(agent->fd, MSG_ACK, NULL, 0) != 0)
        RS_LOG_WARN("failed to send MSG_ACK to host=%s", agent->hostname);

    if (send_msg(agent->fd, MSG_STATUS_REQ, NULL, 0) != 0)
        RS_LOG_WARN("failed to send MSG_STATUS_REQ to host=%s", agent->hostname);
    else
        agent->last_status_req = time(NULL);
}

static void handle_heartbeat(struct controller_agent *agent)
{
    time_t now = time(NULL);

    agent->last_seen = now;
    if (!agent->registered)
        RS_LOG_WARN("heartbeat from unregistered fd=%d", agent->fd);

    if (agent->registered && (now - agent->last_status_req) >= 30) {
        if (send_msg(agent->fd, MSG_STATUS_REQ, NULL, 0) == 0)
            agent->last_status_req = now;
    }
}

static void handle_status_resp(struct controller_agent *agent, const char *payload, uint16_t len)
{
    char status[1024];
    size_t copy_len;

    copy_len = len < (sizeof(status) - 1) ? len : (sizeof(status) - 1);
    memcpy(status, payload, copy_len);
    status[copy_len] = '\0';

    RS_LOG_INFO("status from %s: %s", agent->hostname[0] ? agent->hostname : "<unknown>", status);
}

static void handle_config_push(struct controller_agent *agent, const char *config_dir)
{
    char path[PATH_MAX];
    char *file_buf = NULL;
    uint16_t file_len = 0;
    int ret;

    if (!agent->hostname[0]) {
        send_error_msg(agent->fd, "agent is not registered");
        return;
    }

    ret = snprintf(path, sizeof(path), "%s/%s.yaml", config_dir, agent->hostname);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        send_error_msg(agent->fd, "config path too long");
        return;
    }

    ret = read_file_to_buf(path, &file_buf, &file_len);
    if (ret != 0) {
        RS_LOG_WARN("config read failed host=%s path=%s err=%d", agent->hostname, path, ret);
        send_error_msg(agent->fd, "config not found");
        return;
    }

    if (send_msg(agent->fd, MSG_CONFIG_PUSH, file_buf, file_len) != 0) {
        RS_LOG_WARN("failed pushing config to host=%s", agent->hostname);
    } else {
        RS_LOG_INFO("config pushed host=%s bytes=%u", agent->hostname, (unsigned)file_len);
    }

    free(file_buf);
}

static int setup_listener(int port)
{
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        RS_LOG_WARN("setsockopt SO_REUSEADDR failed: %s", strerror(errno));

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
        RS_LOG_WARN("setsockopt TCP_NODELAY failed: %s", strerror(errno));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, CONTROLLER_MAX_AGENTS) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int alloc_agent_slot(struct controller_agent *agents)
{
    for (int i = 0; i < CONTROLLER_MAX_AGENTS; i++) {
        if (!agents[i].active)
            return i;
    }

    return -1;
}

int rs_controller_run(int port, const char *config_dir)
{
    int listen_fd;
    struct controller_agent agents[CONTROLLER_MAX_AGENTS];
    struct pollfd fds[CONTROLLER_MAX_AGENTS + 1];

    memset(agents, 0, sizeof(agents));
    for (int i = 0; i < CONTROLLER_MAX_AGENTS; i++)
        agents[i].fd = -1;

    listen_fd = setup_listener(port);
    if (listen_fd < 0) {
        RS_LOG_ERROR("failed to listen on port %d: %s", port, strerror(errno));
        return -1;
    }

    RS_LOG_INFO("controller started port=%d config_dir=%s", port, config_dir);

    while (g_running) {
        int nfds = 1;
        int poll_ret;

        fds[0].fd = listen_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        for (int i = 0; i < CONTROLLER_MAX_AGENTS; i++) {
            if (!agents[i].active)
                continue;

            fds[nfds].fd = agents[i].fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        poll_ret = poll(fds, (nfds_t)nfds, 1000);
        if (poll_ret < 0) {
            if (errno == EINTR)
                continue;
            RS_LOG_ERROR("poll failed: %s", strerror(errno));
            break;
        }

        if (poll_ret > 0 && (fds[0].revents & POLLIN)) {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            int cfd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);

            if (cfd >= 0) {
                int slot = alloc_agent_slot(agents);

                if (slot < 0) {
                    RS_LOG_WARN("agent rejected: max agents reached");
                    close(cfd);
                } else {
                    agents[slot].fd = cfd;
                    agents[slot].active = 1;
                    agents[slot].registered = 0;
                    agents[slot].last_seen = time(NULL);
                    RS_LOG_INFO("agent connected fd=%d", cfd);
                }
            }
        }

        for (int i = 1, slot = 0; i < nfds; i++) {
            while (slot < CONTROLLER_MAX_AGENTS && (!agents[slot].active || agents[slot].fd != fds[i].fd))
                slot++;

            if (slot >= CONTROLLER_MAX_AGENTS)
                continue;

            if (!(fds[i].revents & (POLLIN | POLLERR | POLLHUP)))
                continue;

            if (fds[i].revents & (POLLERR | POLLHUP)) {
                close_agent_slot(&agents[slot]);
                continue;
            }

            if (fds[i].revents & POLLIN) {
                struct rs_ctrl_msg hdr;
                char *payload = NULL;

                if (recv_msg(agents[slot].fd, &hdr, &payload) != 0) {
                    close_agent_slot(&agents[slot]);
                    free(payload);
                    continue;
                }

                switch (hdr.type) {
                case MSG_REGISTER:
                    handle_register(&agents[slot], payload, hdr.length);
                    break;
                case MSG_HEARTBEAT:
                    handle_heartbeat(&agents[slot]);
                    break;
                case MSG_STATUS_RESP:
                    handle_status_resp(&agents[slot], payload ? payload : "", hdr.length);
                    break;
                case MSG_CONFIG_PUSH:
                    handle_config_push(&agents[slot], config_dir);
                    break;
                default:
                    RS_LOG_WARN("unsupported msg type=0x%x from host=%s", hdr.type,
                                agents[slot].hostname[0] ? agents[slot].hostname : "<unknown>");
                    send_error_msg(agents[slot].fd, "unsupported message type");
                    break;
                }

                free(payload);
            }
        }

        maybe_drop_stale_agents(agents);
    }

    for (int i = 0; i < CONTROLLER_MAX_AGENTS; i++) {
        if (agents[i].active)
            close_agent_slot(&agents[i]);
    }

    close(listen_fd);
    RS_LOG_INFO("controller stopped");
    return 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s [-p port] [-c config_dir]\n", prog);
}

int main(int argc, char **argv)
{
    int port = CONTROLLER_DEFAULT_PORT;
    const char *config_dir = "/etc/rswitch/controller";
    int opt;

    while ((opt = getopt(argc, argv, "p:c:h")) != -1) {
        switch (opt) {
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535)
                port = CONTROLLER_DEFAULT_PORT;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    signal(SIGINT, controller_signal_handler);
    signal(SIGTERM, controller_signal_handler);

    rs_log_init("rswitch-controller", RS_LOG_LEVEL_INFO);
    return rs_controller_run(port, config_dir);
}
