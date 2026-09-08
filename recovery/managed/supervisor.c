#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int send_registration(int control_fd, pid_t child_pid, int child_pidfd,
                             uint32_t generation, uint32_t connection,
                             uint32_t cookie)
{
    unsigned char record[SWZ_REGISTRATION_BYTES];

    if (swz_registration_record(record, generation, connection, cookie,
                                child_pid, child_pidfd) != 0 ||
        swz_write_record(control_fd, record, sizeof(record)) != 0 ||
        swz_send_fd(control_fd, child_pidfd) != 0) {
        return -1;
    }
    return 0;
}

static int release_exec_gate(int gate_fd)
{
    const unsigned char gate_byte = SWZ_EXEC_GATE_BYTE;

    if (swz_write_full(gate_fd, &gate_byte, sizeof(gate_byte)) != 0 ||
        close(gate_fd) != 0) {
        return -1;
    }
    return 0;
}

static int launch_inetd_child(int accepted_fd, uint32_t generation,
                              uint32_t connection, uint32_t cookie)
{
    int control[2];
    int gate[2];
    pid_t child_pid;
    int child_pidfd = -1;
    int status;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0) {
        return -1;
    }
    if (pipe2(gate, O_CLOEXEC) != 0) {
        close(control[0]);
        close(control[1]);
        return -1;
    }
    child_pid = fork();
    if (child_pid < 0) {
        close(control[0]);
        close(control[1]);
        close(gate[0]);
        close(gate[1]);
        return -1;
    }
    if (child_pid == 0) {
        unsigned char gate_value;

        close(control[0]);
        close(gate[1]);
        if (dup2(accepted_fd, STDIN_FILENO) < 0 ||
            dup2(control[1], SWZ_CONTEXT_FD) < 0 ||
            read(gate[0], &gate_value, sizeof(gate_value)) !=
                (ssize_t)sizeof(gate_value) || gate_value != SWZ_EXEC_GATE_BYTE ||
            read(gate[0], &gate_value, sizeof(gate_value)) != 0 ||
            swz_confine_component("sshd") != 0) {
            _exit(126);
        }
        close(gate[0]);
        execl(SWZ_SSHD_PATH, SWZ_SSHD_PATH, "-i", "-e", "-f",
              SWZ_SSHD_CONFIG_PATH, (char *)NULL);
        _exit(127);
    }
    close(control[1]);
    close(gate[0]);
    child_pidfd = swz_pidfd_open(child_pid);
    if (child_pidfd < 0 ||
        send_registration(control[0], child_pid, child_pidfd, generation,
                          connection, cookie) != 0 ||
        release_exec_gate(gate[1]) != 0) {
        (void)kill(child_pid, SIGTERM);
        close(control[0]);
        close(gate[1]);
        if (child_pidfd >= 0) {
            close(child_pidfd);
        }
        (void)waitpid(child_pid, &status, 0);
        return -1;
    }
    close(control[0]);
    close(child_pidfd);
    close(accepted_fd);
    if (waitpid(child_pid, &status, 0) < 0 && errno != ECHILD) {
        return -1;
    }
    return 0;
}

static int run_listener(void)
{
    int listener;
    uint32_t connection = 0U;

    listener = swz_make_unix_listener(SWZ_SESSION_CONTROL_SOCKET_PATH,
                                      SOCK_STREAM, 0660);
    if (listener < 0) {
        return -1;
    }
    while (!stop_requested) {
        int accepted_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (accepted_fd < 0 && errno == EINTR) {
            continue;
        }
        if (accepted_fd < 0) {
            close(listener);
            return -1;
        }
        ++connection;
        if (launch_inetd_child(accepted_fd, 1U, connection, connection) != 0) {
            close(accepted_fd);
        }
    }
    close(listener);
    (void)unlink(SWZ_SESSION_CONTROL_SOCKET_PATH);
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
