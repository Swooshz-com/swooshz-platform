#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int random_raw32(unsigned char value[32])
{
    size_t offset = 0U;

    while (offset < 32U) {
        ssize_t received = getrandom(value + offset, 32U - offset, 0U);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int send_registration(int control_fd, int child_pidfd,
                             const unsigned char generation[32],
                             const unsigned char connection[32],
                             const unsigned char cookie[32])
{
    unsigned char record[SWZ_REGISTRATION_BYTES];

    return swz_registration_record(record, generation, connection, cookie) == 0 &&
           swz_send_record_fd(control_fd, record, sizeof(record), child_pidfd) == 0;
}

static int release_exec_gate(int gate_fd)
{
    const unsigned char gate_byte = SWZ_EXEC_GATE_BYTE;

    return swz_write_full(gate_fd, &gate_byte, sizeof(gate_byte)) == 0 &&
           close(gate_fd) == 0 ? 0 : -1;
}

static int write_lifecycle_marker(int fd, int retiring)
{
    const char *marker = retiring ? SWZ_RETIRE_MAGIC : SWZ_DISABLE_MAGIC;

    return swz_write_full(fd, marker, 8U);
}

static int make_transcript_fd(void)
{
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "swz-transcript", MFD_CLOEXEC);

    if (fd < 0 || ftruncate(fd, (off_t)SWZ_TRANSCRIPT_BYTES) != 0) {
        close(fd);
        return -1;
    }
    return fd;
#else
    errno = ENOSYS;
    return -1;
#endif
}

static void close_if_unneeded(int fd, const int *keep, size_t keep_count)
{
    size_t index;

    if (fd < 0) {
        return;
    }
    for (index = 0U; index < keep_count; ++index) {
        if (fd == keep[index]) {
            return;
        }
    }
    (void)close(fd);
}

static int launch_custodian(int seed_fd, int agent_listener, int control_fd,
                            int control_peer, int accepted_fd, int network_listener,
                            int session_listener, int gate_read, int gate_write,
                            pid_t *pid)
{
    pid_t child;

    child = fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        const int keep[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                             SWZ_SEED_FD, SWZ_AGENT_LISTENER_FD,
                             SWZ_CUSTODIAN_CONTROL_FD };

        if (dup2(seed_fd, SWZ_SEED_FD) < 0 ||
            dup2(agent_listener, SWZ_AGENT_LISTENER_FD) < 0 ||
            dup2(control_fd, SWZ_CUSTODIAN_CONTROL_FD) < 0 ||
            fcntl(SWZ_SEED_FD, F_SETFD, 0) < 0 ||
            fcntl(SWZ_AGENT_LISTENER_FD, F_SETFD, 0) < 0 ||
            fcntl(SWZ_CUSTODIAN_CONTROL_FD, F_SETFD, 0) < 0 ||
            swz_confine_component("custodian") != 0) {
            _exit(126);
        }
        close_if_unneeded(seed_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(agent_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(control_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(control_peer, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(accepted_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(network_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(session_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(gate_read, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(gate_write, keep, sizeof(keep) / sizeof(keep[0]));
        execl(SWZ_CUSTODIAN_PATH, SWZ_CUSTODIAN_PATH, (char *)NULL);
        _exit(errno == ENOENT ? 127 : 126);
    }
    *pid = child;
    return 0;
}

static int wait_ready(int control_fd)
{
    unsigned char ready[SWZ_READY_BYTES];

    return swz_read_full(control_fd, ready, sizeof(ready)) == 0 &&
           memcmp(ready, SWZ_READY_MAGIC, sizeof(ready)) == 0 ? 0 : -1;
}

static void terminate_sshd_tree(pid_t sshd_pid)
{
    if (sshd_pid > 0) {
        (void)kill(-sshd_pid, SIGTERM);
        (void)kill(sshd_pid, SIGTERM);
    }
}

static int release_sshd(int accepted_fd, int child_gate_fd, int parent_gate_fd,
                        int control_fd, int seed_fd, int network_listener,
                        int agent_listener, int session_listener,
                        int transcript_fd,
                        const unsigned char generation[32],
                        const unsigned char connection[32],
                        const unsigned char cookie[32], pid_t *sshd_pid,
                        int *sshd_pidfd)
{
    pid_t child;
    int pidfd;

    child = fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        unsigned char gate_value;
        const int keep[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                             SWZ_EXEC_GATE_FD, SWZ_TRANSCRIPT_FD };

        if (setpgid(0, 0) != 0 ||
            dup2(accepted_fd, STDIN_FILENO) < 0 ||
            dup2(accepted_fd, STDOUT_FILENO) < 0 ||
            dup2(child_gate_fd, SWZ_EXEC_GATE_FD) < 0 ||
            dup2(transcript_fd, SWZ_TRANSCRIPT_FD) < 0 ||
            read(SWZ_EXEC_GATE_FD, &gate_value, sizeof(gate_value)) !=
                (ssize_t)sizeof(gate_value) || gate_value != SWZ_EXEC_GATE_BYTE ||
            read(SWZ_EXEC_GATE_FD, &gate_value, sizeof(gate_value)) != 0 ||
            swz_confine_component("sshd") != 0) {
            _exit(126);
        }
        close_if_unneeded(seed_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(control_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(network_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(agent_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(session_listener, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(transcript_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(parent_gate_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(accepted_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close_if_unneeded(child_gate_fd, keep, sizeof(keep) / sizeof(keep[0]));
        close(SWZ_EXEC_GATE_FD);
        execl(SWZ_SSHD_PATH, SWZ_SSHD_PATH, "-i", "-e", "-f",
              SWZ_SSHD_CONFIG_PATH, (char *)NULL);
        _exit(127);
    }
    pidfd = swz_pidfd_open(child);
    if (pidfd < 0 || send_registration(control_fd, pidfd, generation,
                                       connection, cookie) != 0) {
        terminate_sshd_tree(child);
        (void)waitpid(child, NULL, 0);
        if (pidfd >= 0) {
            close(pidfd);
        }
        return -1;
    }
    {
        unsigned char acknowledgement[8];

        if (swz_read_full(control_fd, acknowledgement,
                          sizeof(acknowledgement)) != 0 ||
            memcmp(acknowledgement, SWZ_REGISTRATION_ACK,
                   sizeof(acknowledgement)) != 0) {
            terminate_sshd_tree(child);
            (void)waitpid(child, NULL, 0);
            close(pidfd);
            return -1;
        }
    }
    if (release_exec_gate(parent_gate_fd) != 0) {
        terminate_sshd_tree(child);
        (void)waitpid(child, NULL, 0);
        close(pidfd);
        return -1;
    }
    *sshd_pid = child;
    *sshd_pidfd = pidfd;
    return 0;
}

static int send_context_if_authorized(int listener, pid_t sshd_pid,
                                      int sshd_pidfd,
                                      const unsigned char session[32],
                                      const unsigned char generation[32],
                                      const unsigned char connection[32],
                                      const unsigned char cookie[32])
{
    int client;
    pid_t peer_pid;
    uid_t peer_uid;
    gid_t peer_gid;
    unsigned char record[SWZ_CONTEXT_BYTES];

    client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) {
        return errno == EINTR ? 0 : -1;
    }
    if (swz_peer_uidgid(client, &peer_uid, &peer_gid) != 0 ||
        peer_uid != (uid_t)SWZ_RECOVERY_UID ||
        peer_gid != (gid_t)SWZ_RECOVERY_GID ||
        swz_peer_pid(client, &peer_pid) != 0 ||
        !swz_process_is_descendant(peer_pid, sshd_pid) ||
        !swz_process_namespaces_match(peer_pid, sshd_pid) ||
        !swz_pidfd_alive(sshd_pidfd) ||
        swz_peer_domain_is(client, SWZ_EXPECTED_BOOTSTRAP_DOMAIN) != 0 ||
        swz_context_record(record, session, generation, connection, cookie) != 0 ||
        send(client, record, sizeof(record), MSG_NOSIGNAL) != (ssize_t)sizeof(record)) {
        close(client);
        return -1;
    }
    close(client);
    return 0;
}

static int launch_inetd_child(int accepted_fd, int seed_fd, int network_listener,
                              int agent_listener, int session_listener,
                              const unsigned char generation[32],
                              const unsigned char connection[32],
                              const unsigned char cookie[32])
{
    int control[2] = { -1, -1 };
    int gate[2] = { -1, -1 };
    int transcript_fd = -1;
    pid_t custodian_pid = -1;
    pid_t sshd_pid = -1;
    int sshd_pidfd = -1;
    int status;
    unsigned char session[32];
    struct pollfd descriptor;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0 ||
        pipe2(gate, O_CLOEXEC) != 0 || random_raw32(session) != 0 ||
        (transcript_fd = make_transcript_fd()) < 0 ||
        launch_custodian(seed_fd, agent_listener, control[1], control[0], accepted_fd,
                         network_listener, session_listener, gate[0], gate[1],
                         &custodian_pid) != 0) {
        close(control[0]);
        close(control[1]);
        close(gate[0]);
        close(gate[1]);
        close(transcript_fd);
        return -1;
    }
    close(control[1]);
    if (wait_ready(control[0]) != 0 ||
        release_sshd(accepted_fd, gate[0], gate[1], control[0], seed_fd,
                     network_listener, agent_listener, session_listener,
                     transcript_fd,
                     generation, connection,
                     cookie, &sshd_pid, &sshd_pidfd) != 0) {
        if (custodian_pid > 0) {
            (void)kill(custodian_pid, SIGTERM);
        }
        if (sshd_pid > 0) {
            terminate_sshd_tree(sshd_pid);
        }
        close(control[0]);
        close(gate[0]);
        close(gate[1]);
        close(transcript_fd);
        if (custodian_pid > 0) {
            (void)waitpid(custodian_pid, &status, 0);
        }
        if (sshd_pid > 0) {
            (void)waitpid(sshd_pid, &status, 0);
        }
        if (sshd_pidfd >= 0) {
            close(sshd_pidfd);
        }
        return -1;
    }
    close(gate[0]);
    close(transcript_fd);
    descriptor.fd = session_listener;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    while (!stop_requested && swz_pidfd_alive(sshd_pidfd)) {
        int polled = poll(&descriptor, 1U, 100);

        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled < 0) {
            break;
        }
        if (polled > 0 && (descriptor.revents & POLLIN) != 0) {
            if (send_context_if_authorized(session_listener, sshd_pid, sshd_pidfd,
                                            session, generation, connection,
                                            cookie) != 0) {
                break;
            }
        }
    }
    /* Revoke signing before terminating the registered process tree. */
    (void)write_lifecycle_marker(control[0], 0);
    terminate_sshd_tree(sshd_pid);
    (void)waitpid(sshd_pid, &status, 0);
    close(sshd_pidfd);
    (void)write_lifecycle_marker(control[0], 1);
    (void)waitpid(custodian_pid, &status, 0);
    close(control[0]);
    close(accepted_fd);
    return 0;
}

static int run_listener(void)
{
    int network_listener = -1;
    int agent_listener = -1;
    int session_listener = -1;
    int seed_fd = SWZ_SEED_FD;
    uint64_t serial = 0U;

    if (swz_validate_seed_fd(seed_fd) != 0 ||
        (network_listener = swz_make_unix_listener(SWZ_RECOVERY_LISTENER_SOCKET_PATH,
                                                    SOCK_STREAM, 0600)) < 0 ||
        (agent_listener = swz_make_unix_listener(SWZ_HOST_KEY_AGENT_SOCKET_PATH,
                                                  SOCK_STREAM, 0600)) < 0 ||
        (session_listener = swz_make_unix_listener(SWZ_SESSION_CONTROL_SOCKET_PATH,
                                                    SOCK_SEQPACKET, 0660)) < 0) {
        return -1;
    }
    if (chown(SWZ_SESSION_CONTROL_SOCKET_PATH, 0U, 2001U) != 0) {
        close(network_listener);
        close(agent_listener);
        close(session_listener);
        return -1;
    }
    while (!stop_requested) {
        int accepted_fd = accept4(network_listener, NULL, NULL, SOCK_CLOEXEC);
        unsigned char generation[32];
        unsigned char connection[32];
        unsigned char cookie[32];

        if (accepted_fd < 0 && errno == EINTR) {
            continue;
        }
        if (accepted_fd < 0 || random_raw32(generation) != 0 ||
            random_raw32(connection) != 0 || random_raw32(cookie) != 0) {
            close(accepted_fd);
            break;
        }
        ++serial;
        if (serial == 0U || launch_inetd_child(accepted_fd, seed_fd, network_listener,
                                                agent_listener,
                                                session_listener, generation,
                                                connection, cookie) != 0) {
            close(accepted_fd);
            break;
        }
        break;
    }
    close(network_listener);
    close(agent_listener);
    close(session_listener);
    (void)swz_remove_unix_socket(SWZ_RECOVERY_LISTENER_SOCKET_PATH);
    (void)swz_remove_unix_socket(SWZ_HOST_KEY_AGENT_SOCKET_PATH);
    (void)swz_remove_unix_socket(SWZ_SESSION_CONTROL_SOCKET_PATH);
    return 0;
}

int main(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        swz_confine_component("supervisor") != 0) {
        return EXIT_FAILURE;
    }
    return run_listener() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
