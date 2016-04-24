package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>

extern void set_password_buffer_by_index(char *buf, int index,  char value);
extern ssh_string get_oid_by_index(ssh_string *oids, int index);
extern int pointer_to_int(void *userdata);

typedef const char *conststr;

extern void install_auth_callback(ssh_callbacks callbacks);
extern void install_log_callback(ssh_callbacks callbacks);
extern void install_connection_status_callback(ssh_callbacks callbacks);
extern void install_global_request_callback(ssh_callbacks callbacks);
extern void install_channel_open_request_x11_callback(ssh_callbacks callbacks);
extern void install_channel_open_request_auth_agent_callback(ssh_callbacks callbacks);
extern int set_callbacks(ssh_session session, ssh_callbacks callbacks);

extern void install_channel_data_callback(ssh_channel_callbacks callbacks);
extern void install_channel_eof_callback(ssh_channel_callbacks callbacks);
extern void install_channel_close_callback(ssh_channel_callbacks callbacks);
extern void install_channel_signal_callback(ssh_channel_callbacks callbacks);
extern void install_channel_exit_status_callback(ssh_channel_callbacks callbacks);
extern void install_channel_exit_signal_callback(ssh_channel_callbacks callbacks);
extern void install_channel_pty_request_callback(ssh_channel_callbacks callbacks);
extern void install_channel_shell_request_callback(ssh_channel_callbacks callbacks);
extern void install_channel_auth_agent_req_callback(ssh_channel_callbacks callbacks);
extern void install_channel_x11_req_callback(ssh_channel_callbacks callbacks);
extern void install_channel_pty_window_change_callback(ssh_channel_callbacks callbacks);
extern void install_channel_exec_request_callback(ssh_channel_callbacks callbacks);
extern void install_channel_env_request_callback(ssh_channel_callbacks callbacks);
extern void install_channel_subsystem_request_callback(ssh_channel_callbacks callbacks);
extern int set_channel_callbacks(ssh_channel channel, ssh_channel_callbacks callbacks);

extern void install_auth_password_callback(ssh_server_callbacks callbacks);
extern void install_auth_none_callback(ssh_server_callbacks callbacks);
extern void install_auth_gssapi_mic_callback(ssh_server_callbacks callbacks);
extern void install_auth_pubkey_callback(ssh_server_callbacks callbacks);
extern void install_service_request_callback(ssh_server_callbacks callbacks);
extern void install_channel_open_request_session_callback(ssh_server_callbacks callbacks);
extern void install_gssapi_select_oid_callback(ssh_server_callbacks callbacks);
extern void install_gssapi_accept_sec_ctx_callback(ssh_server_callbacks callbacks);
extern void install_gssapi_verify_mic_callback(ssh_server_callbacks callbacks);
extern int set_server_callbacks(ssh_session session, ssh_server_callbacks callbacks);

// why allocate structs from C ?
//  cgo has more strict, not allow passing "Go pointer to Go pointer" since 1.6
//
extern ssh_callbacks new_session_callbacks();
extern ssh_channel_callbacks new_channel_callbacks();
extern ssh_server_callbacks new_server_callbacks();
*/
import "C"

import "unsafe"

var NULL = unsafe.Pointer(nil)

type SessionCallbacks struct {
	cstruct *C.struct_ssh_callbacks_struct
	// SSH authentication callback. for client-side
	// prompt	Prompt to be displayed.
	// maxlen	Max length of password
	// echo		Enable or disable the echo of what you type.
	// verify	Should the password be verified?
	//
	// returns:
	//  password	The password
	//  ok			false if you don't want to return any
	OnSshAuth func(prompt string, maxlen int, echo, verify bool) (string, bool)
	// All logging messages will go through this callback
	OnSessionLog func(session Session, priority int, message string)
	// Connect status
	OnConnectProgress func(percentage float32)
	// All global request will go through this callback.
	OnGlobalRequest func(session Session, message Message)
	// Handles an SSH new channel open X11 request.
	//
	// This happens when the server sends back an X11 connection attempt. This is a
	// client-side API
	//
	// Warning:
	//  The channel pointer returned by this callback must be closed by the
	//  application.
	OnOpenX11 func(session Session, originatorAddress string, originatorPort int) Channel
	// Handles an SSH new channel open "auth-agent" request.
	//
	// This happens when the server sends back an "auth-agent" connection attempt.
	// This is a client-side API
	//
	// Warning:
	//  The channel pointer returned by this callback must be closed by the
	//  application.
	OnOpenAuthAgent func(session Session) Channel
}

func (callbacks *SessionCallbacks) Free() {
	if callbacks.cstruct != nil {
		C.free(unsafe.Pointer(callbacks.cstruct))
	}
	callbacks.cstruct = nil
}

func (s Session) SetCallbacks(cbs *SessionCallbacks) error {
	callbacks := C.new_session_callbacks()
	callbacks.userdata = unsafe.Pointer(cbs)
	cbs.cstruct = callbacks
	if cbs.OnSshAuth != nil {
		C.install_auth_callback(callbacks)
	}
	if cbs.OnSessionLog != nil {
		C.install_log_callback(callbacks)
	}
	if cbs.OnConnectProgress != nil {
		C.install_connection_status_callback(callbacks)
	}
	if cbs.OnGlobalRequest != nil {
		C.install_global_request_callback(callbacks)
	}
	if cbs.OnOpenX11 != nil {
		C.install_channel_open_request_x11_callback(callbacks)
	}
	if cbs.OnOpenAuthAgent != nil {
		C.install_channel_open_request_auth_agent_callback(callbacks)
	}
	err := apiError("ssh_set_callbacks", C.set_callbacks(s.ptr, callbacks))
	if err != nil {
		cbs.Free()
	}
	return err
}

type ChannelCallbacks struct {
	cstruct *C.struct_ssh_channel_callbacks_struct
	// Called when data is available on a channel
	OnChannelData    func(session Session, channel Channel, data []byte, isStderr bool) int
	OnChannelRawData func(session Session, channel Channel, data_ptr unsafe.Pointer, length uint, isStderr bool) int
	// Called when a channel receives EOF
	OnChannelEOF func(session Session, channel Channel)
	// Called when a channel is closed by remote peer
	OnChannelClose func(session Session, channel Channel)
	// Called when a channel has received a signal
	// signal	the signal name (without the SIG prefix)
	OnChannelSignal func(session Session, channel Channel, signal string)
	// Called when a channel has received an exit status
	OnChannelExitStatus func(session Session, channel Channel, status int)
	// Called when a channel has received an exit signal
	// signal	the signal name (without the SIG prefix)
	// core		a boolean telling wether a core has been dumped or not
	// errmsg	the description of the exception
	// lang		the language of the description (format: RFC 3066)
	OnChannelExitSignal func(session Session, channel Channel, signal string, core bool, errmsg, lang string)
	// SSH channel PTY request from a client.
	// term		The type of terminal emulation
	// width	width of the terminal, in characters
	// height	height of the terminal, in characters
	// pxwidth	width of the terminal, in pixels
	// pxheight	height of the terminal, in pixels
	//
	// return true if accepted
	OnChannelNewPty func(session Session, channel Channel, term string, width, height, pxwidth, pwheight int) bool
	// SSH channel Shell request from a client.
	// return true if accepted
	OnChannelShellRequest func(session Session, channel Channel) bool
	// SSH auth-agent-request from the client.
	//
	// This request is sent by a client when agent forwarding is available. Server
	// is free to ignore this callback, no answer is expected.
	OnChannelAuthAgentRequest func(session Session, channel Channel)
	// SSH X11 request from the client.
	//
	// This request is sent by a client when X11 forwarding is requested(and
	// available). Server is free to ignore this callback, no answer is expected.
	OnChannelX11Request func(session Session, channel Channel, singleConnection bool, authProtocol, authCookie string, screenNumber int)
	// SSH channel PTY windows change (terminal size) from a client.
	// width	width of the terminal, in characters
	// height	height of the terminal, in characters
	// pxwidth	width of the terminal, in pixels
	// pxheight	height of the terminal, in pixels
	//
	// return true if accepted
	OnChannelChangePtyWindow func(session Session, channel Channel, width, height, pxwidth, pwheight int) bool
	// SSH channel Exec request from a client.
	// return true if the request accepted
	OnChannelExecRequest func(session Session, channel Channel, cmdline string) bool
	// SSH channel environment request from a client.
	// return true if env request accepted
	OnChannelEnvRequest func(session Session, channel Channel, envName, envValue string) bool
	// SSH channel subsystem request from a client.
	// return true if accepted
	OnChannelSubSystemRequest func(session Session, channel Channel, subsystem string) bool
}

func (callbacks *ChannelCallbacks) Free() {
	if callbacks.cstruct != nil {
		C.free(unsafe.Pointer(callbacks.cstruct))
	}
	callbacks.cstruct = nil
}

func (c Channel) SetCallbacks(cbs *ChannelCallbacks) error {
	callbacks := C.new_channel_callbacks()
	callbacks.userdata = unsafe.Pointer(cbs)
	cbs.cstruct = callbacks
	if cbs.OnChannelRawData != nil {
		C.install_channel_data_callback(callbacks)
	} else if cbs.OnChannelData != nil {
		C.install_channel_data_callback(callbacks)
	}
	if cbs.OnChannelEOF != nil {
		C.install_channel_eof_callback(callbacks)
	}
	if cbs.OnChannelClose != nil {
		C.install_channel_close_callback(callbacks)
	}
	if cbs.OnChannelSignal != nil {
		C.install_channel_signal_callback(callbacks)
	}
	if cbs.OnChannelExitStatus != nil {
		C.install_channel_exit_status_callback(callbacks)
	}
	if cbs.OnChannelExitSignal != nil {
		C.install_channel_exit_signal_callback(callbacks)
	}
	if cbs.OnChannelNewPty != nil {
		C.install_channel_pty_request_callback(callbacks)
	}
	if cbs.OnChannelShellRequest != nil {
		C.install_channel_shell_request_callback(callbacks)
	}
	if cbs.OnChannelAuthAgentRequest != nil {
		C.install_channel_auth_agent_req_callback(callbacks)
	}
	if cbs.OnChannelX11Request != nil {
		C.install_channel_x11_req_callback(callbacks)
	}
	if cbs.OnChannelChangePtyWindow != nil {
		C.install_channel_pty_window_change_callback(callbacks)
	}
	if cbs.OnChannelExecRequest != nil {
		C.install_channel_exec_request_callback(callbacks)
	}
	if cbs.OnChannelEnvRequest != nil {
		C.install_channel_env_request_callback(callbacks)
	}
	if cbs.OnChannelSubSystemRequest != nil {
		C.install_channel_subsystem_request_callback(callbacks)
	}
	return apiError("ssh_set_channel_callbacks", C.set_channel_callbacks(c.ptr, callbacks))
}

type ServerCallbacks struct {
	cstruct *C.struct_ssh_server_callbacks_struct
	// Tries to authenticates user with password
	OnAuthPassword func(session Session, user, password string) int
	// Tries to authenticates user with the "none" method which is anonymous or
	// passwordless.
	OnAuthNone func(session Session, user string) int
	// callbacks referred from: libssh/callbacks.h

	// Available return values for SSH authenticate callbacks:
	//  SSH_AUTH_SUCCESS Authentication is accepted.
	//  SSH_AUTH_PARTIAL Partial authentication, more authentication means are
	//    needed
	//  SSH_AUTH_DENIED Authentication failed.

	// Tries to authenticates user with the "gssapi-with-mic" method
	//
	// Warning:
	//  Implementations should verify that parameter user matches in some way the
	//  principal. user and principal can be different. Only the latter is
	//  guaranteed to be safe
	OnSshAuthGssapiMic func(session Session, user, principle string) int
	// Tries to authenticates user with public key
	// signatureState:
	//  SSH_PUBLICKEY_STATE_NONE if the key is not signed (simple public key
	//  probe)
	//  SSH_PUBLICKEY_STATE_VALID if the signature is valid
	//  Others values should be replied with a SSH_AUTH_DENIED
	OnAuthPublickKey func(session Session, user string, pubkey Key, signatureState int) int
	// Handles an SSH service request.
	// return true if allowed
	OnSessionServiceRequest func(session Session, service string) bool
	// Handles an SSH new channel open session request.
	//
	// Warning:
	//  The channel pointer returned by this callback must be closed by the
	//  application.
	OnOpenChannel func(session Session) Channel
	// handle the beginning of a GSSAPI authentication, server side.
	OnSessionGssapiSelectOid func(session Session, user string, oids []string) string
	// handle the negociation of a security context, server side.
	// input_token input token provided by client
	// return output of the gssapi accept_sec_context method, NULL after
	// completion.
	OnGssapiAcceptSecurityContext func(session Session, inputToken string) (string, bool)
	OnGssapiVerifyMic             func(session Session, mic string, data []byte) error
}

func (callbacks *ServerCallbacks) Free() {
	if callbacks.cstruct != nil {
		C.free(unsafe.Pointer(callbacks.cstruct))
		callbacks.cstruct = nil
	}
}

func (s Session) SetServerCallbacks(cbs *ServerCallbacks) error {
	callbacks := C.new_server_callbacks()
	callbacks.userdata = unsafe.Pointer(cbs)
	cbs.cstruct = callbacks
	if cbs.OnAuthPassword != nil {
		C.install_auth_password_callback(callbacks)
	}
	if cbs.OnAuthNone != nil {
		C.install_auth_none_callback(callbacks)
	}
	if cbs.OnSshAuthGssapiMic != nil {
		C.install_auth_gssapi_mic_callback(callbacks)
	}
	if cbs.OnAuthPublickKey != nil {
		C.install_auth_pubkey_callback(callbacks)
	}
	if cbs.OnSessionServiceRequest != nil {
		C.install_service_request_callback(callbacks)
	}
	if cbs.OnOpenChannel != nil {
		C.install_channel_open_request_session_callback(callbacks)
	}
	if cbs.OnSessionGssapiSelectOid != nil {
		C.install_gssapi_select_oid_callback(callbacks)
	}
	if cbs.OnGssapiAcceptSecurityContext != nil {
		C.install_gssapi_accept_sec_ctx_callback(callbacks)
	}
	if cbs.OnGssapiVerifyMic != nil {
		C.install_gssapi_verify_mic_callback(callbacks)
	}
	return apiError("ssh_set_server_callbacks", C.set_server_callbacks(s.ptr, callbacks))
}

type PacketCallbacks struct {
	cstruct C.struct_ssh_packet_callbacks_struct
	// Prototype for a packet callback, to be called when a new packet arrives
	// return true if the packet is parsed
	// return false if the packet needs to continue processing
	OnSessionPacket func(session Session, packetType int, buffer Buffer) bool
}

//export auth_callback
func auth_callback(prompt C.conststr, buf *C.char, length C.size_t, echo C.int, verify C.int, userdata unsafe.Pointer) C.int {
	callbacks := (*SessionCallbacks)(userdata)
	password_str, ok := callbacks.OnSshAuth(C.GoString(prompt), int(length), echo != 0, verify != 0)
	if !ok {
		return -1
	}
	password := []byte(password_str)
	i := 0
	passwordLength := len(password)
	if int(length)-1 < passwordLength {
		passwordLength = int(length) - 1
	}
	for ; i < passwordLength; i++ {
		C.set_password_buffer_by_index(buf, C.int(i), C.char(password[i]))
	}
	C.set_password_buffer_by_index(buf, C.int(i), C.char(0x0))
	return 0
}

//export auth_gssapi_mic_callback
func auth_gssapi_mic_callback(session C.ssh_session, user, principle C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	return C.int(callbacks.OnSshAuthGssapiMic(Session{session}, C.GoString(user), C.GoString(principle)))
}

//export gssapi_select_oid_callback
func gssapi_select_oid_callback(session C.ssh_session, user C.conststr, n_oids C.int, oids *C.ssh_string, userdata unsafe.Pointer) C.ssh_string {
	callbacks := (*ServerCallbacks)(userdata)
	oidSlice := make([]string, int(n_oids))
	for i := 0; i < int(n_oids); i++ {
		oid := C.get_oid_by_index(oids, C.int(i))
		oidSlice[i] = SshString{oid}.String()
	}
	selected := callbacks.OnSessionGssapiSelectOid(Session{session}, C.GoString(user), oidSlice)
	return NewStringFrom(selected).ptr
}

//export gssapi_accept_sec_ctx_callback
func gssapi_accept_sec_ctx_callback(session C.ssh_session, input_token C.ssh_string, output_token *C.ssh_string, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	outputToken, accepted := callbacks.OnGssapiAcceptSecurityContext(Session{session}, SshString{input_token}.String())
	if accepted {
		if err := NewStringFrom(outputToken).Copy(SshString{*output_token}); err == nil {
			return SSH_OK
		}
	}
	return SSH_ERROR
}

//export gssapi_verify_mic_callback
func gssapi_verify_mic_callback(session C.ssh_session, mic C.ssh_string, data_ptr unsafe.Pointer, size C.size_t, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	data := copyData(data_ptr, size)
	if callbacks.OnGssapiVerifyMic(Session{session}, SshString{mic}.String(), data) != nil {
		return SSH_ERROR
	}
	return SSH_OK
}

//export auth_none_callback
func auth_none_callback(session C.ssh_session, user C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	return C.int(callbacks.OnAuthNone(Session{session}, C.GoString(user)))
}

//export auth_password_callback
func auth_password_callback(session C.ssh_session, user, password C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	return C.int(callbacks.OnAuthPassword(Session{session}, C.GoString(user), C.GoString(password)))
}

//export auth_pubkey_callback
func auth_pubkey_callback(session C.ssh_session, user C.conststr, pubkey *C.struct_ssh_key_struct,
	signature_state C.char, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	return C.int(callbacks.OnAuthPublickKey(Session{session}, C.GoString(user), Key{pubkey}, int(signature_state)))
}

//export channel_auth_agent_req_callback
func channel_auth_agent_req_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelAuthAgentRequest(Session{session}, Channel{channel})
}

//export channel_close_callback
func channel_close_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelClose(Session{session}, Channel{channel})
}

// SSH channel data callback.
//
// Called when data is available on a channel
type ChannelDataCallback interface {
	OnChannelData(session Session, channel Channel, data []byte, isStderr bool) int
}

type ChannelRawDataCallback interface {
	OnChannelRawData(session Session, channel Channel, data_ptr unsafe.Pointer, length uint, isStderr bool) int
}

//export channel_data_callback
func channel_data_callback(session C.ssh_session, channel C.ssh_channel,
	data_ptr unsafe.Pointer, len C.uint32_t, is_stderr C.int, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelRawData != nil {
		return C.int(callbacks.OnChannelRawData(Session{session}, Channel{channel}, data_ptr, uint(len), is_stderr != 0))
	} else if callbacks.OnChannelData != nil {
		return C.int(callbacks.OnChannelData(Session{session}, Channel{channel}, copyData(data_ptr, len), is_stderr != 0))
	}
	return SSH_ERROR
}

//export channel_env_request_callback
func channel_env_request_callback(session C.ssh_session, channel C.ssh_channel,
	env_name, env_value C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelEnvRequest(Session{session}, Channel{channel}, C.GoString(env_name), C.GoString(env_value)) {
		// 0 if the env request is accepted
		return 0
	} else {
		// 1 if the request is denied
		return 1
	}
}

//export channel_eof_callback
func channel_eof_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelEOF(Session{session}, Channel{channel})
}

//export channel_exec_request_callback
func channel_exec_request_callback(session C.ssh_session, channel C.ssh_channel,
	cmdline C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelExecRequest(Session{session}, Channel{channel}, C.GoString(cmdline)) {
		return 0
	} else {
		return 1
	}
}

//export channel_exit_signal_callback
func channel_exit_signal_callback(session C.ssh_session, channel C.ssh_channel,
	signal C.conststr, core C.int, errmsg, lang C.conststr, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelExitSignal(Session{session}, Channel{channel}, C.GoString(signal), core != 0, C.GoString(errmsg), C.GoString(lang))
}

//export channel_exit_status_callback
func channel_exit_status_callback(session C.ssh_session, channel C.ssh_channel, status C.int, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelExitStatus(Session{session}, Channel{channel}, int(status))
}

//export channel_open_request_auth_agent_callback
func channel_open_request_auth_agent_callback(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
	callbacks := (*SessionCallbacks)(userdata)
	return callbacks.OnOpenAuthAgent(Session{session}).ptr
}

//export channel_open_request_session_callback
func channel_open_request_session_callback(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
	callbacks := (*ServerCallbacks)(userdata)
	return callbacks.OnOpenChannel(Session{session}).ptr
}

//export channel_open_request_x11_callback
func channel_open_request_x11_callback(session C.ssh_session, originator_address C.conststr, originator_port C.int, userdata unsafe.Pointer) C.ssh_channel {
	callbacks := (*SessionCallbacks)(userdata)
	return callbacks.OnOpenX11(Session{session}, C.GoString(originator_address), int(originator_port)).ptr
}

//export channel_pty_request_callback
func channel_pty_request_callback(session C.ssh_session, channel C.ssh_channel,
	term C.conststr, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelNewPty(Session{session}, Channel{channel}, C.GoString(term), int(width), int(height), int(pxwidth), int(pwheight)) {
		return 0
	}
	return 1
}

//export channel_pty_window_change_callback
func channel_pty_window_change_callback(session C.ssh_session, channel C.ssh_channel, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelChangePtyWindow(Session{session}, Channel{channel}, int(width), int(height), int(pxwidth), int(pwheight)) {
		return 0
	}
	return 1
}

//export channel_shell_request_callback
func channel_shell_request_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelShellRequest(Session{session}, Channel{channel}) {
		return 0
	}
	return 1
}

//export channel_signal_callback
func channel_signal_callback(session C.ssh_session, channel C.ssh_channel, signal C.conststr, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelSignal(Session{session}, Channel{channel}, C.GoString(signal))
}

//export channel_subsystem_request_callback
func channel_subsystem_request_callback(session C.ssh_session, channel C.ssh_channel,
	subsystem C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ChannelCallbacks)(userdata)
	if callbacks.OnChannelSubSystemRequest(Session{session}, Channel{channel}, C.GoString(subsystem)) {
		return 0
	}
	return 1
}

//export channel_x11_req_callback
func channel_x11_req_callback(session C.ssh_session, channel C.ssh_channel,
	single_connection C.int, auth_protocol, auth_cookie C.conststr,
	screen_number C.uint32_t, userdata unsafe.Pointer) {
	callbacks := (*ChannelCallbacks)(userdata)
	callbacks.OnChannelX11Request(Session{session}, Channel{channel}, single_connection != 0, C.GoString(auth_protocol), C.GoString(auth_cookie), int(screen_number))
}

//export global_request_callback
func global_request_callback(session C.ssh_session, message C.ssh_message, userdata unsafe.Pointer) {
	callbacks := (*SessionCallbacks)(userdata)
	callbacks.OnGlobalRequest(Session{session}, Message{message})
}

//export session_log_callback
func session_log_callback(session C.ssh_session, priority C.int, message C.conststr, userdata unsafe.Pointer) {
	callbacks := (*SessionCallbacks)(userdata)
	callbacks.OnSessionLog(Session{session}, int(priority), C.GoString(message))
}

//export service_request_callback
func service_request_callback(session C.ssh_session, service C.conststr, userdata unsafe.Pointer) C.int {
	callbacks := (*ServerCallbacks)(userdata)
	if callbacks.OnSessionServiceRequest(Session{session}, C.GoString(service)) {
		return 0
	}
	return -1
}

//export connection_status_callback
func connection_status_callback(userdata unsafe.Pointer, status C.float) {
	callbacks := (*SessionCallbacks)(userdata)
	callbacks.OnConnectProgress(float32(status))
}

//export packet_callback
func packet_callback(session C.ssh_session, packetType C.uint8_t, packet C.ssh_buffer, userdata unsafe.Pointer) C.int {
	callbacks := (*PacketCallbacks)(userdata)
	if callbacks.OnSessionPacket(Session{session}, int(packetType), Buffer{packet}) {
		return C.SSH_PACKET_USED
	}
	return C.SSH_PACKET_NOT_USED
}

//export status_callback
func status_callback(session C.ssh_session, status C.float, userdata unsafe.Pointer) {
	//callbacks := (*SessionCallbacks)(userdata)
	//callbacks.OnSessionConnectProgress(Session{session}, float32(status))
}
