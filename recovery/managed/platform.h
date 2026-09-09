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
#define SWZ_RECOVERY_LISTENER_SOCKET_PATH "/run/swz/recovery-network.sock"
#define SWZ_SSHD_PATH "/opt/swz/openssh/sbin/sshd"
#define SWZ_SSHD_CONFIG_PATH "/etc/ssh/recovery_sshd_config"
#define SWZ_CUSTODIAN_PATH "/usr/local/libexec/swz-custodian"
#define SWZ_SUPERVISOR_PATH "/usr/local/libexec/swz-supervisor"
#define SWZ_DISPATCHER_PATH "/usr/local/libexec/swz-dispatcher"
#define SWZ_BOOTSTRAP_PATH "/usr/local/libexec/swz-bootstrap"
#define SWZ_BROKER_PATH "/usr/local/libexec/swz-broker"
#define SWZ_AGENT_PATH "/usr/local/libexec/swz-agent"
#define SWZ_QUALIFIED_ARTIFACT_ROOT "/var/lib/swooshz-recovery"
#define SWZ_QUALIFIED_ARTIFACT_PATH "/var/lib/swooshz-recovery/qualified-artifact"
#define SWZ_RESTORE_TARGET_PATH "/run/swz/qualified-restored-artifact"

#define SWZ_EXPECTED_SSHD_DOMAIN "swz_sshd_t"
#define SWZ_EXPECTED_BOOTSTRAP_DOMAIN "swz_bootstrap_t"
#define SWZ_EXPECTED_BROKER_DOMAIN "swz_broker_t"
#define SWZ_EXPECTED_AGENT_DOMAIN "swz_agent_t"
#define SWZ_RECOVERY_UID 2001U
#define SWZ_RECOVERY_GID 2001U

#define SWZ_REGISTRATION_MAGIC "SWZREG01"
#define SWZ_REGISTRATION_BYTES 104U
#define SWZ_CONTEXT_MAGIC "SWZCTX01"
#define SWZ_CONTEXT_BYTES 136U
#define SWZ_READY_MAGIC "SWZRDY01"
#define SWZ_READY_BYTES 8U
#define SWZ_REGISTRATION_ACK "SWZRGOK1"
#define SWZ_DISABLE_MAGIC "SWZDIS01"
#define SWZ_RETIRE_MAGIC "SWZRET01"
#define SWZ_EXEC_GATE_BYTE 0xA5U
#define SWZ_SEED_FD 3
#define SWZ_AGENT_LISTENER_FD 4
#define SWZ_CUSTODIAN_CONTROL_FD 5
#define SWZ_EXEC_GATE_FD 6
#define SWZ_TRANSCRIPT_FD 7
#define SWZ_AGENT_BUNDLE_FD 8
#define SWZ_AGENT_SOURCE_FD 4
#define SWZ_AGENT_RESTORE_FD 5
#define SWZ_AGENT_RESULT_CONTEXT_FD 6
#define SWZ_RESTORE_WORKER_INPUT_FD 9
#define SWZ_RESTORE_WORKER_TARGET_FD 10
#define SWZ_TRANSCRIPT_BYTES 264U
#define SWZ_MAX_SEED_BYTES 32U
#define SWZ_MAX_FRAME_BYTES 65536U
#define SWZ_MAX_CONTROL_PAYLOAD_BYTES 4096U
#define SWZ_RESULT_CONTEXT_BIND_MAGIC "SWZRCB01"
#define SWZ_RESULT_CONTEXT_FINAL_MAGIC "SWZRCF01"
#define SWZ_RESULT_CONTEXT_VERSION 1U
#define SWZ_RESULT_CONTEXT_BIND_KIND 1U
#define SWZ_RESULT_CONTEXT_FINAL_KIND 2U
#define SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES 2048U
#define SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES 10144U
#define SWZ_RESULT_CONTEXT_CAPTURE_MAX_BYTES 4096U
#define SWZ_RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES 12192U
#define SWZ_RESULT_CONTEXT_STREAM_MAX_BYTES 12288U
#define SWZ_AGENT_BUNDLE_MAGIC "LAUNCH_AGENT_DESCRIPTORS_V1"
#define SWZ_AGENT_BUNDLE_RECORD_BYTES 32U

int swz_write_full(int fd, const void *buf, size_t len);
int swz_read_full(int fd, void *buf, size_t len);
int swz_read_bounded(int fd, void *buf, size_t capacity, size_t *length);
int swz_sha256(const void *data, size_t len, unsigned char out[32]);
int swz_file_sha256(const char *path, unsigned char out[32]);
int swz_managed_hash(const char *domain, const unsigned char *const *parts,
                    const size_t *lengths, size_t count,
                    unsigned char out[32]);
int swz_store_commitment(const char *domain, const unsigned char *bytes,
                         size_t length, char out[80]);
int swz_hex(const unsigned char *bytes, size_t length, char *out,
            size_t capacity);
int swz_parse_ipv4(const char *text, unsigned char out[4]);
int swz_validate_seed_fd(int fd);
int swz_read_seed_exact(int fd, unsigned char seed[SWZ_MAX_SEED_BYTES]);
int swz_disable_dump_core(void);
int swz_set_cloexec(int fd);
int swz_set_nonblock(int fd);
int swz_make_unix_listener(const char *path, int type, mode_t mode);
int swz_remove_unix_socket(const char *path);
int swz_peer_uidgid(int fd, uid_t *uid, gid_t *gid);
int swz_peer_pid(int fd, pid_t *pid);
int swz_peer_domain_is(int fd, const char *expected_domain);
int swz_same_socket_peer(int fd, pid_t expected_pid);
int swz_process_is_descendant(pid_t pid, pid_t ancestor);
int swz_process_namespaces_match(pid_t first, pid_t second);
int swz_pidfd_open(pid_t pid);
int swz_pidfd_alive(int pidfd);
int swz_pidfd_get_pid(int pidfd, pid_t *pid);
int swz_send_fd(int socket_fd, int fd);
int swz_recv_fd(int socket_fd);
int swz_send_record_fd(int socket_fd, const void *record, size_t length, int fd);
int swz_recv_record_fd(int socket_fd, void *record, size_t length, int *fd);
int swz_send_agent_descriptor_bundle(int socket_fd, const int fds[3]);
int swz_recv_agent_descriptor_bundle(int socket_fd, int fds[3]);
int swz_confine_component(const char *component);
int swz_write_record(int fd, const void *record, size_t length);

int swz_registration_record(unsigned char out[SWZ_REGISTRATION_BYTES],
                            const unsigned char generation[32],
                            const unsigned char connection[32],
                            const unsigned char cookie[32]);
int swz_context_record(unsigned char out[SWZ_CONTEXT_BYTES],
                       const unsigned char session[32],
                       const unsigned char generation[32],
                       const unsigned char connection[32],
                       const unsigned char cookie[32]);

#endif
