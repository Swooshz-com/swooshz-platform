#ifndef SWZ_MANAGED_PLATFORM_H
#define SWZ_MANAGED_PLATFORM_H

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

struct swz_namespace_identity {
	dev_t mount_device;
	ino_t mount_inode;
	dev_t pid_device;
	ino_t pid_inode;
	dev_t net_device;
	ino_t net_inode;
};

int swz_read_full(int fd, void *buffer, size_t length, int timeout_ms);
int swz_read_exact_eof(int fd, uint8_t *buffer, size_t length, int timeout_ms);
int swz_write_full(int fd, const void *buffer, size_t length);
int swz_close_on_exec(int fd);
int swz_set_nonblocking(int fd);
int swz_random_bytes(uint8_t *out, size_t length);
void swz_zeroize(void *buffer, size_t length);

int swz_sha256(const uint8_t *data, size_t length, uint8_t digest[32]);
int swz_sha256_file(const char *path, uint8_t digest[32]);
int swz_managed_hash(const char *domain, const uint8_t *const parts[], const size_t lengths[], size_t count, uint8_t digest[32]);
int swz_store_commitment(const char *domain, const uint8_t *data, size_t length, char out[75]);
int swz_hex_decode(const char *text, uint8_t *out, size_t out_length);
int swz_literal_ipv4(const char *text, uint8_t out[4]);

int swz_validate_seed_fd(int fd, uid_t owner, gid_t group);
int swz_read_seed_fd(int fd, uint8_t seed[32]);
int swz_load_ed25519_public_file(const char *path, uint8_t public_key[32]);

int swz_is_descendant(pid_t pid, pid_t ancestor);
int swz_pidfd_open(pid_t pid);
int swz_pidfd_send_signal(int pidfd, int signal_number);
int swz_pidfd_is_live(int pidfd);
int swz_pidfd_target_pid(int pidfd, pid_t *pid);
int swz_wait_final(pid_t pid, int pidfd, int timeout_ms, int *status);
int swz_process_starttime(pid_t pid, uint64_t *starttime);
int swz_process_namespace(pid_t pid, struct swz_namespace_identity *identity);
int swz_pidfd_process_in_tree(int pidfd, pid_t candidate, const struct swz_namespace_identity *expected_namespace);
int swz_peer_credentials(int fd, pid_t *pid, uid_t *uid, gid_t *gid);
int swz_peer_domain_matches(int fd, const char *expected_domain);
int swz_process_domain_matches(const char *expected_domain);
int swz_get_socket_cookie(int fd, uint64_t *cookie);

int swz_send_fd(int channel_fd, int fd_to_send, const void *payload, size_t payload_length);
int swz_receive_fd(int channel_fd, int *received_fd, void *payload, size_t payload_capacity, size_t *payload_length);
int swz_secure_socket_path(const char *path, uid_t owner);
int swz_parse_fd(const char *text, int *fd);

int swz_build_registration_record(uint8_t out[SWZ_REGISTRATION_BYTES], const uint8_t generation_raw32[32], const uint8_t accepted_connection_raw32[32], const uint8_t connection_cookie_raw32[32]);
int swz_validate_registration_record(const uint8_t record[SWZ_REGISTRATION_BYTES]);
int swz_build_context_record(uint8_t out[SWZ_CONTEXT_BYTES], const uint8_t session_raw32[32], const uint8_t generation_raw32[32], const uint8_t accepted_connection_raw32[32], const uint8_t connection_cookie_raw32[32]);
int swz_validate_context_record(const uint8_t record[SWZ_CONTEXT_BYTES]);
int swz_read_context_record(int fd, uint8_t session_raw32[32], uint8_t generation_raw32[32], uint8_t accepted_connection_raw32[32], uint8_t connection_cookie_raw32[32]);

int swz_confine_process(void);

#endif
