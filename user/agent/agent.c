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
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <limits.h>

#include "agent.h"
#include "../controller/controller.h"
#include "../../bpf/core/module_abi.h"

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define AGENT_OUTPUT_DIR "/var/lib/rswitch/agent"
#define AGENT_CONFIG_PATH AGENT_OUTPUT_DIR "/pushed_config.yaml"
#define AGENT_PROFILE_PATH AGENT_OUTPUT_DIR "/pushed_profile.yaml"

static volatile sig_atomic_t g_running = 1;

static void agent_signal_handler(int signo)
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

static int ensure_output_dir(void)
{
    struct stat st;

    if (stat(AGENT_OUTPUT_DIR, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -ENOTDIR;
    }

    if (mkdir("/var/lib/rswitch", 0755) != 0 && errno != EEXIST)
        return -errno;
    if (mkdir(AGENT_OUTPUT_DIR, 0755) != 0 && errno != EEXIST)
        return -errno;
    return 0;
}

static int write_payload_file(const char *path, const char *data, uint16_t len)
{
    FILE *fp;

    if (ensure_output_dir() != 0)
        return -1;

    fp = fopen(path, "wb");
    if (!fp)
        return -1;

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int read_uptime_sec(uint32_t *uptime_sec)
{
    FILE *fp;
    double uptime = 0.0;

    fp = fopen("/proc/uptime", "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%lf", &uptime) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *uptime_sec = (uint32_t)uptime;
    return 0;
}

static uint32_t count_sysfs_bpf_entries(void)
{
    DIR *dir;
    struct dirent *ent;
    uint32_t count = 0;

    dir = opendir("/sys/fs/bpf");
    if (!dir)
        return 0;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        count++;
    }

    closedir(dir);
    return count;
}

static int build_status_json(char *buf, size_t size)
{
    char hostname[64] = {0};
    uint32_t uptime_sec = 0;
    uint32_t modules;

    if (gethostname(hostname, sizeof(hostname) - 1) != 0)
        snprintf(hostname, sizeof(hostname), "unknown");

    if (read_uptime_sec(&uptime_sec) != 0)
        uptime_sec = 0;

    modules = count_sysfs_bpf_entries();
    return snprintf(buf, size,
                    "{\"hostname\":\"%s\",\"uptime_sec\":%u,\"num_modules\":%u,\"abi\":%u}",
                    hostname, uptime_sec, modules, RS_ABI_VERSION);
}

static int send_register_msg(int fd)
{
    struct rs_agent_info info;
    uint32_t uptime = 0;
    int ret;

    memset(&info, 0, sizeof(info));
    if (gethostname(info.hostname, sizeof(info.hostname) - 1) != 0)
        snprintf(info.hostname, sizeof(info.hostname), "unknown");

    snprintf(info.version, sizeof(info.version), "rSwitch-agent-2.1");
    if (read_uptime_sec(&uptime) != 0)
        uptime = 0;

    info.num_modules = htonl(count_sysfs_bpf_entries());
    info.uptime_sec = htonl(uptime);

    ret = send_msg(fd, MSG_REGISTER, &info, (uint16_t)sizeof(info));
    if (ret != 0)
        return ret;

    RS_LOG_INFO("registration sent hostname=%s", info.hostname);
    return 0;
}

static int connect_controller(const char *host, int port)
{
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
        RS_LOG_WARN("setsockopt TCP_NODELAY failed: %s", strerror(errno));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int rs_agent_run(const char *controller_host, int controller_port)
{
    while (g_running) {
        int fd;
        time_t last_heartbeat;

        fd = connect_controller(controller_host, controller_port);
        if (fd < 0) {
            RS_LOG_WARN("connect failed to %s:%d: %s", controller_host, controller_port, strerror(errno));
            sleep(AGENT_RECONNECT_SEC);
            continue;
        }

        RS_LOG_INFO("connected to controller %s:%d", controller_host, controller_port);

        if (send_register_msg(fd) != 0) {
            RS_LOG_WARN("failed to send register");
            close(fd);
            sleep(AGENT_RECONNECT_SEC);
            continue;
        }

        last_heartbeat = 0;

        while (g_running) {
            struct pollfd pfd;
            time_t now = time(NULL);
            int poll_ret;

            if (last_heartbeat == 0 || (now - last_heartbeat) >= CONTROLLER_HEARTBEAT_SEC) {
                if (send_msg(fd, MSG_HEARTBEAT, NULL, 0) != 0) {
                    RS_LOG_WARN("heartbeat send failed");
                    break;
                }
                last_heartbeat = now;
            }

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;

            poll_ret = poll(&pfd, 1, 1000);
            if (poll_ret < 0) {
                if (errno == EINTR)
                    continue;
                RS_LOG_WARN("poll failed: %s", strerror(errno));
                break;
            }

            if (poll_ret == 0)
                continue;

            if (pfd.revents & (POLLERR | POLLHUP)) {
                RS_LOG_WARN("controller disconnected");
                break;
            }

            if (pfd.revents & POLLIN) {
                struct rs_ctrl_msg hdr;
                char *payload = NULL;

                if (recv_msg(fd, &hdr, &payload) != 0) {
                    free(payload);
                    RS_LOG_WARN("receive failed from controller");
                    break;
                }

                if (hdr.type == MSG_ACK) {
                    RS_LOG_INFO("controller ACK received");
                } else if (hdr.type == MSG_STATUS_REQ) {
                    char status_buf[512];
                    int json_len = build_status_json(status_buf, sizeof(status_buf));

                    if (json_len < 0)
                        json_len = 0;
                    if (json_len >= (int)sizeof(status_buf))
                        json_len = (int)sizeof(status_buf) - 1;

                    if (send_msg(fd, MSG_STATUS_RESP, status_buf, (uint16_t)json_len) != 0) {
                        free(payload);
                        RS_LOG_WARN("failed to send status response");
                        break;
                    }
                } else if (hdr.type == MSG_CONFIG_PUSH) {
                    if (write_payload_file(AGENT_CONFIG_PATH, payload ? payload : "", hdr.length) != 0)
                        RS_LOG_ERROR("failed to write pushed config %s", AGENT_CONFIG_PATH);
                    else
                        RS_LOG_INFO("config updated %s (%u bytes)", AGENT_CONFIG_PATH, (unsigned)hdr.length);
                } else if (hdr.type == MSG_PROFILE_PUSH) {
                    if (write_payload_file(AGENT_PROFILE_PATH, payload ? payload : "", hdr.length) != 0)
                        RS_LOG_ERROR("failed to write pushed profile %s", AGENT_PROFILE_PATH);
                    else
                        RS_LOG_INFO("profile updated %s (%u bytes)", AGENT_PROFILE_PATH, (unsigned)hdr.length);
                } else if (hdr.type == MSG_ERROR) {
                    char errbuf[256];
                    size_t copy_len = hdr.length < (sizeof(errbuf) - 1) ? hdr.length : (sizeof(errbuf) - 1);

                    memcpy(errbuf, payload ? payload : "", copy_len);
                    errbuf[copy_len] = '\0';
                    RS_LOG_WARN("controller MSG_ERROR: %s", errbuf);
                } else {
                    RS_LOG_WARN("unknown controller msg type=0x%x", hdr.type);
                }

                free(payload);
            }
        }

        close(fd);
        if (g_running) {
            RS_LOG_INFO("reconnecting in %d seconds", AGENT_RECONNECT_SEC);
            sleep(AGENT_RECONNECT_SEC);
        }
    }

    return 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s [-h host] [-p port]\n", prog);
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1";
    int port = CONTROLLER_DEFAULT_PORT;
    int opt;

    while ((opt = getopt(argc, argv, "h:p:?")) != -1) {
        switch (opt) {
        case 'h':
            host = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535)
                port = CONTROLLER_DEFAULT_PORT;
            break;
        case '?':
        default:
            usage(argv[0]);
            return opt == '?' ? 0 : 1;
        }
    }

    signal(SIGINT, agent_signal_handler);
    signal(SIGTERM, agent_signal_handler);
    rs_log_init("rswitch-agent", RS_LOG_LEVEL_INFO);
    return rs_agent_run(host, port);
}
