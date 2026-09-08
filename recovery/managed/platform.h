#ifndef SWZ_MANAGED_PLATFORM_H
#define SWZ_MANAGED_PLATFORM_H

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SWZ_PRODUCTION_SEED_PATH "/var/lib/swooshz-recovery/host-key/ed25519.seed"
#define SWZ_HOST_PUBLIC_KEY_PATH "/etc/ssh/recovery_host_ed25519_key.pub"
#define SWZ_HOST_KEY_AGENT_SOCKET_PATH "/run/swz/recovery-hostkey-agent.sock"
#define SWZ_SESSION_CONTROL_SOCKET_PATH "/run/swz/recovery-session-control.sock"
#define SWZ_SSHD_PATH "/opt/swz/openssh/sbin/sshd"
#define SWZ_SSHD_CONFIG_PATH "/etc/ssh/recovery_sshd_config"
#define SWZ_CUSTODIAN_PATH "/usr/local/libexec/swz-custodian"
#define SWZ_SUPERVISOR_PATH "/usr/local/libexec/swz-supervisor"
#define SWZ_DISPATCHER_PATH "/usr/local/libexec/swz-dispatcher"
#define SWZ_BOOTSTRAP_PATH "/usr/local/libexec/swz-bootstrap"
#define SWZ_BROKER_PATH "/usr/local/libexec/swz-broker"
#define SWZ_AGENT_PATH "/usr/local/libexec/swz-agent"

#define SWZ_EXPECTED_SSHD_DOMAIN "swz_sshd_t"
#define SWZ_EXPECTED_BOOTSTRAP_DOMAIN "swz_bootstrap_t"
#define SWZ_EXPECTED_BROKER_DOMAIN "swz_broker_t"
#define SWZ_EXPECTED_AGENT_DOMAIN "swz_agent_t"

#define SWZ_REGISTRATION_MAGIC "SWZREG01"
#define SWZ_REGISTRATION_BYTES 104U
#define SWZ_CONTEXT_MAGIC "SWZCTX01"
#define SWZ_CONTEXT_BYTES 136U
#define SWZ_EXEC_GATE_BYTE 0xA5U
#define SWZ_CONTEXT_FD 3

#define SWZ_MAX_SEED_BYTES 32U
#define SWZ_MAX_FRAME_BYTES 65536U
#define SWZ_MAX_CONTROL_PAYLOAD_BYTES 4096U

int swz_write_full(int fd, const void *buf, size_t len);
int swz_read_full(int fd, void *buf, size_t len);
int swz_read_bounded(int fd, void *buf, size_t capacity, size_t *length);
int swz_sha256(const void *data, size_t len, unsigned char out[32]);
int swz_managed_hash(const char *domain, const unsigned char *const *parts,
                    const size_t *lengths, size_t count,
                    unsigned char out[32]);
int swz_store_commitment(const char *domain, const unsigned char *bytes,
                         size_t length, char out[80]);
int swz_hex(const unsigned char *bytes, size_t length, char *out,
            size_t capacity);
int swz_parse_ipv4(const char *text, unsigned char out[4]);
int swz_validate_seed_fd(int fd);
int swz_set_cloexec(int fd);
int swz_set_nonblock(int fd);
int swz_make_unix_listener(const char *path, int type, mode_t mode);
int swz_peer_uidgid(int fd, uid_t *uid, gid_t *gid);
int swz_same_socket_peer(int fd, pid_t expected_pid);
int swz_process_is_descendant(pid_t pid, pid_t ancestor);
int swz_pidfd_open(pid_t pid);
int swz_pidfd_alive(int pidfd);
int swz_send_fd(int socket_fd, int fd);
int swz_recv_fd(int socket_fd);
int swz_confine_component(const char *component);
int swz_write_record(int fd, const void *record, size_t length);

int swz_registration_record(unsigned char out[SWZ_REGISTRATION_BYTES],
                            uint32_t generation, uint32_t connection,
                            uint32_t cookie, pid_t pid, int pidfd);
int swz_context_record(unsigned char out[SWZ_CONTEXT_BYTES], uint32_t session,
                       uint32_t generation, uint32_t connection,
                       uint32_t cookie);

#endif

