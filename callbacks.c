#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include "_cgo_export.h"

void set_password_buffer_by_index( char *buf, int index,  char value) {
	buf[index] = value;
}

typedef void (*connect_status_callback)(void *userdata, float status);

ssh_string get_oid_by_index(ssh_string *oids, int index)  {
	return oids[index];
}

int pointer_to_int(void *ptr) {
    return (int)ptr;
}

// for ssh_callbacks
extern int auth_callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata);
extern void log_callback(ssh_session session, int priority, const char *message, void *userdata);
extern void connection_status_callback(void *userdata, float status);
extern void global_request_callback(ssh_session session, ssh_message message, void *userdata);
extern ssh_channel channel_open_request_x11_callback(ssh_session session, const char * originator_address, int originator_port, void *userdata);
extern ssh_channel channel_open_request_auth_agent_callback(ssh_session session, void *userdata);

void install_auth_callback(ssh_callbacks callbacks) { callbacks->auth_function = auth_callback; }
void install_log_callback(ssh_callbacks callbacks) { callbacks->log_function = log_callback; }
void install_connection_status_callback(ssh_callbacks callbacks) { callbacks->connect_status_function = connection_status_callback; }
void install_global_request_callback(ssh_callbacks callbacks) { callbacks->global_request_function = global_request_callback; }
void install_channel_open_request_x11_callback(ssh_callbacks callbacks) { callbacks->channel_open_request_x11_function = channel_open_request_x11_callback; }
void install_channel_open_request_auth_agent_callback(ssh_callbacks callbacks) { callbacks->channel_open_request_auth_agent_function = channel_open_request_auth_agent_callback; }

ssh_callbacks new_callbacks(int index) {
	ssh_callbacks callbacks = (ssh_callbacks)(malloc(sizeof(struct ssh_callbacks_struct)));
    memset(callbacks, 0, sizeof(struct ssh_callbacks_struct));
	callbacks->userdata = (void *)index;
	return callbacks;
}

int set_callbacks(ssh_session session, ssh_callbacks callbacks) {
	ssh_callbacks_init(callbacks);
	return ssh_set_callbacks(session, callbacks);
}

// for ssh_channel_callbacks
extern int channel_data_callback(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata);
extern void channel_eof_callback(ssh_session session, ssh_channel channel, void *userdata);
extern void channel_close_callback(ssh_session session, ssh_channel channel, void *userdata);
extern void channel_signal_callback(ssh_session session, ssh_channel channel, const char *signal, void *userdata);
extern void channel_exit_status_callback(ssh_session session, ssh_channel channel, int exit_status, void *userdata);
extern void channel_exit_signal_callback(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata);
extern int channel_pty_request_callback(ssh_session session, ssh_channel channel, const char *term, int width, int height, int pxwidth, int pwheight, void *userdata);
extern int channel_shell_request_callback(ssh_session session, ssh_channel channel, void *userdata);
extern void channel_auth_agent_req_callback(ssh_session session, ssh_channel channel, void *userdata);
extern void channel_x11_req_callback(ssh_session session, ssh_channel channel, int single_connection, const char *auth_protocol, const char *auth_cookie, uint32_t screen_number, void *userdata);
extern int channel_pty_window_change_callback(ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pwheight, void *userdata);
extern int channel_exec_request_callback(ssh_session session, ssh_channel channel, const char *command, void *userdata);
extern int channel_env_request_callback(ssh_session session, ssh_channel channel, const char *env_name, const char *env_value, void *userdata);
extern int channel_subsystem_request_callback(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata);

void install_channel_data_callback(ssh_channel_callbacks callbacks) { callbacks->channel_data_function = channel_data_callback; }
void install_channel_eof_callback(ssh_channel_callbacks callbacks) { callbacks->channel_eof_function = channel_eof_callback; }
void install_channel_close_callback(ssh_channel_callbacks callbacks) { callbacks->channel_close_function = channel_close_callback; }
void install_channel_signal_callback(ssh_channel_callbacks callbacks) { callbacks->channel_signal_function = channel_signal_callback; }
void install_channel_exit_status_callback(ssh_channel_callbacks callbacks) { callbacks->channel_exit_status_function = channel_exit_status_callback; }
void install_channel_exit_signal_callback(ssh_channel_callbacks callbacks) { callbacks->channel_exit_signal_function = channel_exit_signal_callback; }
void install_channel_pty_request_callback(ssh_channel_callbacks callbacks) { callbacks->channel_pty_request_function = channel_pty_request_callback; }
void install_channel_shell_request_callback(ssh_channel_callbacks callbacks) { callbacks->channel_shell_request_function = channel_shell_request_callback; }
void install_channel_auth_agent_req_callback(ssh_channel_callbacks callbacks) { callbacks->channel_auth_agent_req_function = channel_auth_agent_req_callback; }
void install_channel_x11_req_callback(ssh_channel_callbacks callbacks) { callbacks->channel_x11_req_function = channel_x11_req_callback; }
void install_channel_pty_window_change_callback(ssh_channel_callbacks callbacks) { callbacks->channel_pty_window_change_function = channel_pty_window_change_callback; }
void install_channel_exec_request_callback(ssh_channel_callbacks callbacks) { callbacks->channel_exec_request_function = channel_exec_request_callback; }
void install_channel_env_request_callback(ssh_channel_callbacks callbacks) { callbacks->channel_env_request_function = channel_env_request_callback; }
void install_channel_subsystem_request_callback(ssh_channel_callbacks callbacks) { callbacks->channel_subsystem_request_function = channel_subsystem_request_callback; }

ssh_channel_callbacks new_channel_callbacks(int index) {
	ssh_channel_callbacks callbacks = (ssh_channel_callbacks)(malloc(sizeof(struct ssh_channel_callbacks_struct)));
    memset(callbacks, 0, sizeof(struct ssh_channel_callbacks_struct));
	callbacks->userdata = (void *)index;
	return callbacks;
}

int set_channel_callbacks(ssh_channel channel, ssh_channel_callbacks callbacks) {
	ssh_callbacks_init(callbacks);
	return ssh_set_channel_callbacks(channel, callbacks);
}

// for ssh_server_callbacks
extern int auth_password_callback(ssh_session session, const char *user, const char *password, void *userdata);
extern int auth_none_callback(ssh_session session, const char *user, void *userdata);
extern int auth_gssapi_mic_callback(ssh_session session, const char *user, const char *principal, void *userdata);
extern int auth_pubkey_callback(ssh_session session, const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata);
extern int service_request_callback(ssh_session session, const char *service, void *userdata);
extern ssh_channel channel_open_request_session_callback(ssh_session session, void *userdata);
extern ssh_string gssapi_select_oid_callback(ssh_session session, const char *user, int n_oid, ssh_string *oids, void *userdata);
extern int gssapi_accept_sec_ctx_callback(ssh_session session, ssh_string input_token, ssh_string *output_token, void *userdata);
extern int gssapi_verify_mic_callback(ssh_session session, ssh_string mic, void *mic_buffer, size_t mic_buffer_size, void *userdata);

void install_auth_password_callback(ssh_server_callbacks callbacks) { callbacks->auth_password_function = auth_password_callback; }
void install_auth_none_callback(ssh_server_callbacks callbacks) { callbacks->auth_none_function = auth_none_callback; }
void install_auth_gssapi_mic_callback(ssh_server_callbacks callbacks) { callbacks->auth_gssapi_mic_function = auth_gssapi_mic_callback; }
void install_auth_pubkey_callback(ssh_server_callbacks callbacks) { callbacks->auth_pubkey_function = auth_pubkey_callback; }
void install_service_request_callback(ssh_server_callbacks callbacks) { callbacks->service_request_function = service_request_callback; }
void install_channel_open_request_session_callback(ssh_server_callbacks callbacks) { callbacks->channel_open_request_session_function = channel_open_request_session_callback; }
void install_gssapi_select_oid_callback(ssh_server_callbacks callbacks) { callbacks->gssapi_select_oid_function = gssapi_select_oid_callback; }
void install_gssapi_accept_sec_ctx_callback(ssh_server_callbacks callbacks) { callbacks->gssapi_accept_sec_ctx_function = gssapi_accept_sec_ctx_callback; }
void install_gssapi_verify_mic_callback(ssh_server_callbacks callbacks) { callbacks->gssapi_verify_mic_function = gssapi_verify_mic_callback; }

ssh_server_callbacks new_server_callbacks(int index) {
	ssh_server_callbacks callbacks = (ssh_server_callbacks)(malloc(sizeof(struct ssh_server_callbacks_struct)));
    memset(callbacks, 0, sizeof(struct ssh_server_callbacks_struct));
	callbacks->userdata = (void *)index;
	return callbacks;
}

int set_server_callbacks(ssh_session session, ssh_server_callbacks callbacks) {
	ssh_callbacks_init(callbacks);
	return ssh_set_server_callbacks(session, callbacks);
}
