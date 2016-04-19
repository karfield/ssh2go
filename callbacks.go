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

void set_password_buffer_by_index( char *buf, int index,  char value) {
	buf[index] = value;
}

void session_callbacks_init(ssh_callbacks p) {
	ssh_callbacks_init(p);
}

void channel_callbacks_init(ssh_channel_callbacks p) {
	ssh_callbacks_init(p);
}

void server_callbacks_init(ssh_server_callbacks p) {
	ssh_callbacks_init(p);
}

typedef void (*connect_status_function)(void *userdata, float status);

ssh_string get_oid_by_index(ssh_string *oids, int index)  {
	return oids[index];
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

var NULL = unsafe.Pointer(nil)

func (s Session) SetCallbacks(impls interface{}) error {
	cbs := C.struct_ssh_callbacks_struct{}
	if cb, ok := impls.(SshAuthCallback); ok {
		cbs.auth_function = wrapSshAuthCallback(cb)
	}
	if cb, ok := impls.(SessionLogCallback); ok {
		cbs.log_function = wrapSessionLogCallback(cb)
	}
	if cb, ok := impls.(ConnectProgressCallback); ok {
		cbs.connect_status_function = wrapConnectProgressCallback(cb)
	}
	if cb, ok := impls.(GlobalRequestCallback); ok {
		cbs.global_request_function = wrapGlobalRequestCallback(cb)
	}
	if cb, ok := impls.(SessionConnectProgressCallback); ok {
		cbs.connect_status_function = wrapSessionConnectProgressCallback(cb)
	}
	if cb, ok := impls.(OpenX11Callback); ok {
		cbs.channel_open_request_x11_function = wrapOpenX11Callback(cb)
	}
	if cb, ok := impls.(OpenAuthAgentCallbak); ok {
		cbs.channel_open_request_auth_agent_function = wrapOpenAuthAgentCallbak(cb)
	}
	C.session_callbacks_init(&cbs)
	if C.ssh_set_callbacks(s.ptr, &cbs) == SSH_OK {
		return nil
	}
	return errors.New("ssh_set_callbacks() != SSH_OK")
}

func (c Channel) SetCallbacks(impls interface{}) error {
	cbs := C.struct_ssh_channel_callbacks_struct{}
	if cb, ok := impls.(ChannelRawDataCallback); ok {
		cbs.channel_data_function = wrapChannelDataCallback(cb, nil)
	} else if cb2, ok := impls.(ChannelDataCallback); ok {
		cbs.channel_data_function = wrapChannelDataCallback(nil, cb2)
	}
	if cb, ok := impls.(ChannelEofCallback); ok {
		cbs.channel_eof_function = wrapChannelEofCallback(cb)
	}
	if cb, ok := impls.(ChannelCloseCallback); ok {
		cbs.channel_close_function = wrapChannelCloseCallback(cb)
	}
	if cb, ok := impls.(ChannelSignalCallback); ok {
		cbs.channel_signal_function = wrapChannelSignalCallback(cb)
	}
	if cb, ok := impls.(ChannelExitStatusCallback); ok {
		cbs.channel_exit_status_function = wrapChannelExitStatusCallback(cb)
	}
	if cb, ok := impls.(ChannelExitSignalCallback); ok {
		cbs.channel_exit_signal_function = wrapChannelExitSignalCallback(cb)
	}
	if cb, ok := impls.(ChannelNewPtyRequestCallback); ok {
		cbs.channel_pty_request_function = wrapChannelNewPtyRequestCallback(cb)
	}
	if cb, ok := impls.(ChanelShellRequestCallback); ok {
		cbs.channel_shell_request_function = wrapChanelShellRequestCallback(cb)
	}
	if cb, ok := impls.(AuthAgentRequestCallback); ok {
		cbs.channel_auth_agent_req_function = wrapAuthAgentRequestCallback(cb)
	}
	if cb, ok := impls.(ChannelX11RequestCallback); ok {
		cbs.channel_x11_req_function = wrapChannelX11RequestCallback(cb)
	}
	if cb, ok := impls.(ChannelChangePtyWindowCallback); ok {
		cbs.channel_pty_window_change_function = wrapChannelChangePtyWindowCallback(cb)
	}
	if cb, ok := impls.(ChannelExecRequestCallback); ok {
		cbs.channel_exec_request_function = wrapChannelExecRequestCallback(cb)
	}
	if cb, ok := impls.(ChannelEnvRequestCallback); ok {
		cbs.channel_env_request_function = wrapChannelEnvRequestCallback(cb)
	}
	if cb, ok := impls.(ChannelSubSystemRequestCallback); ok {
		cbs.channel_subsystem_request_function = wrapChannelSubSystemRequestCallback(cb)
	}
	C.channel_callbacks_init(&cbs)
	if C.ssh_set_channel_callbacks(c.ptr, &cbs) == SSH_OK {
		return nil
	}
	return errors.New("ssh_set_channel_callbacks() != SSH_OK")
}

func (s Session) SetServerCallbacks(impls interface{}) error {
	cbs := C.struct_ssh_server_callbacks_struct{}
	if cb, ok := impls.(AuthPasswordCallback); ok {
		cbs.auth_password_function = wrapAutPasswordCallback(cb)
	}
	if cb, ok := impls.(AuthNoneCallback); ok {
		cbs.auth_none_function = wrapAuthNoneCallback(cb)
	}
	if cb, ok := impls.(AuthGssapiMicCallback); ok {
		cbs.auth_gssapi_mic_function = wrapAuthGssapiMicCallback(cb)
	}
	if cb, ok := impls.(AuthPublicKeyCallback); ok {
		cbs.auth_pubkey_function = wrapAuthPublickKeyCallback(cb)
	}
	if cb, ok := impls.(SessionServiceRequest); ok {
		cbs.service_request_function = wrapSessionServiceRequest(cb)
	}
	if cb, ok := impls.(OpenChannelCallback); ok {
		cbs.channel_open_request_session_function = wrapOpenChannelCallback(cb)
	}
	if cb, ok := impls.(GssapiSelectOidCallback); ok {
		cbs.gssapi_select_oid_function = wrapGssapiSelectOidCallback(cb)
	}
	if cb, ok := impls.(GssapiAcceptSecurityContextCallback); ok {
		cbs.gssapi_accept_sec_ctx_function = wrapGssapiAcceptSecurityContextCallback(cb)
	}
	if cb, ok := impls.(GssapiVerifyMicCallback); ok {
		cbs.gssapi_verify_mic_function = wrapGssapiVerifyMicCallback(cb)
	}
	C.server_callbacks_init(&cbs)
	if C.ssh_set_server_callbacks(s.ptr, &cbs) == SSH_OK {
		return nil
	}
	return errors.New("ssh_server_callbacks_struct() != SSH_OK")
}

// callbacks referred from: libssh/libssh.h

// SSH authentication callback. for client-side
type SshAuthCallback interface {
	// prompt	Prompt to be displayed.
	// maxlen	Max length of password
	// echo		Enable or disable the echo of what you type.
	// verify	Should the password be verified?
	//
	// returns:
	//  password	The password
	//  ok			false if you don't want to return any

	OnSshAuth(prompt string, maxlen int, echo, verify bool) (string, bool)
}

func wrapSshAuthCallback(callback SshAuthCallback) C.ssh_auth_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(prompt *C.char, buf *C.char, length C.size_t, echo C.int, verify C.int, userdata unsafe.Pointer) C.int {
			password_str, ok := callback.OnSshAuth(C.GoString(prompt), int(length), echo != 0, verify != 0)
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
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_auth_callback(ptr)
}

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
type AuthGssapiMicCallback interface {
	OnSshAuthGssapiMic(session Session, user, principle string) int
}

func wrapAuthGssapiMicCallback(callback AuthGssapiMicCallback) C.ssh_auth_gssapi_mic_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, user, principle *C.char, userdata unsafe.Pointer) C.int {
			return C.int(callback.OnSshAuthGssapiMic(Session{session}, C.GoString(user), C.GoString(principle)))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_auth_gssapi_mic_callback(ptr)
}

// Tries to authenticates user with the "none" method which is anonymous or
// passwordless.
type AuthNoneCallback interface {
	OnAuthNone(session Session, user string) int
}

func wrapAuthNoneCallback(callback AuthNoneCallback) C.ssh_auth_none_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, user *C.char, userdata unsafe.Pointer) C.int {
			return C.int(callback.OnAuthNone(Session{session}, C.GoString(user)))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_auth_none_callback(ptr)
}

// Tries to authenticates user with password
type AuthPasswordCallback interface {
	OnAuthPassword(session Session, user, password string) int
}

func wrapAutPasswordCallback(callback AuthPasswordCallback) C.ssh_auth_password_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, user *C.char, password *C.char, userdata unsafe.Pointer) C.int {
			return C.int(callback.OnAuthPassword(Session{session}, C.GoString(user), C.GoString(password)))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_auth_password_callback(ptr)
}

// Tries to authenticates user with public key
type AuthPublicKeyCallback interface {
	// signatureState:
	//  SSH_PUBLICKEY_STATE_NONE if the key is not signed (simple public key
	//  probe)
	//  SSH_PUBLICKEY_STATE_VALID if the signature is valid
	//  Others values should be replied with a SSH_AUTH_DENIED
	OnAuthPublickKey(session Session, user string, pubkey Key, signatureState int) int
}

func wrapAuthPublickKeyCallback(callback AuthPublicKeyCallback) C.ssh_auth_pubkey_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, user *C.char, pubkey *C.struct_ssh_key_struct, signature_state C.char, userdata unsafe.Pointer) C.int {
			return C.int(callback.OnAuthPublickKey(Session{session}, C.GoString(user), Key{pubkey}, int(signature_state)))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_auth_pubkey_callback(ptr)

}

// SSH auth-agent-request from the client.
//
// This request is sent by a client when agent forwarding is available. Server
// is free to ignore this callback, no answer is expected.
type AuthAgentRequestCallback interface {
	OnChannelAuthAgentRequest(session Session, channel Channel)
}

func wrapAuthAgentRequestCallback(callback AuthAgentRequestCallback) C.ssh_channel_auth_agent_req_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
			callback.OnChannelAuthAgentRequest(Session{session}, Channel{channel})
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_auth_agent_req_callback(ptr)
}

// SSH channel close callback.
//
// Called when a channel is closed by remote peer
type ChannelCloseCallback interface {
	OnChannelClose(session Session, channel Channel)
}

func wrapChannelCloseCallback(callback ChannelCloseCallback) C.ssh_channel_close_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
			callback.OnChannelClose(Session{session}, Channel{channel})
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_close_callback(ptr)
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

func wrapChannelDataCallback(processRawData ChannelRawDataCallback, processData ChannelDataCallback) C.ssh_channel_data_callback {
	ptr := NULL
	if processRawData != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, data_ptr unsafe.Pointer, len C.uint32_t, is_stderr C.int, userdata unsafe.Pointer) C.int {
			return C.int(processRawData.OnChannelRawData(Session{session}, Channel{channel}, data_ptr, uint(len), is_stderr != 0))
		}
		ptr = unsafe.Pointer(&wrapper)
	} else if processData != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, data_ptr unsafe.Pointer, len C.uint32_t, is_stderr C.int, userdata unsafe.Pointer) C.int {
			return C.int(processData.OnChannelData(Session{session}, Channel{channel}, copyData(data_ptr, len), is_stderr != 0))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_data_callback(ptr)
}

// SSH channel environment request from a client.
type ChannelEnvRequestCallback interface {
	// return true if env request accepted
	OnChannelEnvRequest(session Session, channel Channel, envName, envValue string) bool
}

func wrapChannelEnvRequestCallback(callback ChannelEnvRequestCallback) C.ssh_channel_env_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, env_name, env_value *C.char, userdata unsafe.Pointer) C.int {
			if callback.OnChannelEnvRequest(Session{session}, Channel{channel}, C.GoString(env_name), C.GoString(env_value)) {
				// 0 if the env request is accepted
				return 0
			} else {
				// 1 if the request is denied
				return 1
			}
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_env_request_callback(ptr)
}

// SSH channel eof callback.
//
// Called when a channel receives EOF
type ChannelEofCallback interface {
	OnChannelEOF(session Session, channel Channel)
}

func wrapChannelEofCallback(callback ChannelEofCallback) C.ssh_channel_eof_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
			callback.OnChannelEOF(Session{session}, Channel{channel})
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_eof_callback(ptr)
}

// SSH channel Exec request from a client.
type ChannelExecRequestCallback interface {
	// return true if the request accepted
	OnChannelExecRequest(session Session, channel Channel, cmdline string) bool
}

func wrapChannelExecRequestCallback(callback ChannelExecRequestCallback) C.ssh_channel_exec_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, cmdline *C.char, userdata unsafe.Pointer) C.int {
			if callback.OnChannelExecRequest(Session{session}, Channel{channel}, C.GoString(cmdline)) {
				return 0
			} else {
				return 1
			}
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_exec_request_callback(ptr)
}

// SSH channel exit signal callback.
//
// Called when a channel has received an exit signal
type ChannelExitSignalCallback interface {
	// signal	the signal name (without the SIG prefix)
	// core		a boolean telling wether a core has been dumped or not
	// errmsg	the description of the exception
	// lang		the language of the description (format: RFC 3066)
	OnChannelExitSignal(session Session, channel Channel, signal string, core bool, errmsg, lang string)
}

func wrapChannelExitSignalCallback(callback ChannelExitSignalCallback) C.ssh_channel_exit_signal_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, signal *C.char, core C.int, errmsg, lang *C.char, userdata unsafe.Pointer) {
			callback.OnChannelExitSignal(Session{session}, Channel{channel}, C.GoString(signal), core != 0, C.GoString(errmsg), C.GoString(lang))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_exit_signal_callback(ptr)
}

// SSH channel exit status callback.
//
// Called when a channel has received an exit status
type ChannelExitStatusCallback interface {
	OnChannelExitStatus(session Session, channel Channel, status int)
}

func wrapChannelExitStatusCallback(callback ChannelExitStatusCallback) C.ssh_channel_exit_status_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, status C.int, userdata unsafe.Pointer) {
			callback.OnChannelExitStatus(Session{session}, Channel{channel}, int(status))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_exit_status_callback(ptr)
}

// Handles an SSH new channel open "auth-agent" request.
//
// This happens when the server sends back an "auth-agent" connection attempt.
// This is a client-side API
//
// Warning:
//  The channel pointer returned by this callback must be closed by the
//  application.
type OpenAuthAgentCallbak interface {
	OnOpenAuthAgent(session Session) Channel
}

func wrapOpenAuthAgentCallbak(callback OpenAuthAgentCallbak) C.ssh_channel_open_request_auth_agent_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
			return callback.OnOpenAuthAgent(Session{session}).ptr
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_open_request_auth_agent_callback(ptr)
}

// Handles an SSH new channel open session request.
//
// Warning:
//  The channel pointer returned by this callback must be closed by the
//  application.
type OpenChannelCallback interface {
	OnOpenChannel(session Session) Channel
}

func wrapOpenChannelCallback(callback OpenChannelCallback) C.ssh_channel_open_request_session_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
			return callback.OnOpenChannel(Session{session}).ptr
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_open_request_session_callback(ptr)
}

// Handles an SSH new channel open X11 request.
//
// This happens when the server sends back an X11 connection attempt. This is a
// client-side API
//
// Warning:
//  The channel pointer returned by this callback must be closed by the
//  application.
type OpenX11Callback interface {
	OnOpenX11(session Session, originatorAddress string, originatorPort int) Channel
}

func wrapOpenX11Callback(callback OpenX11Callback) C.ssh_channel_open_request_x11_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, originator_address *C.char, originator_port C.int, userdata unsafe.Pointer) C.ssh_channel {
			return callback.OnOpenX11(Session{session}, C.GoString(originator_address), int(originator_port)).ptr
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_open_request_x11_callback(ptr)
}

// SSH channel PTY request from a client.
type ChannelNewPtyRequestCallback interface {
	// term		The type of terminal emulation
	// width	width of the terminal, in characters
	// height	height of the terminal, in characters
	// pxwidth	width of the terminal, in pixels
	// pxheight	height of the terminal, in pixels
	//
	// return true if accepted
	OnChannelNewPty(session Session, channel Channel, term string, width, height, pxwidth, pwheight int) bool
}

func wrapChannelNewPtyRequestCallback(callback ChannelNewPtyRequestCallback) C.ssh_channel_pty_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, term *C.char, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
			if callback.OnChannelNewPty(Session{session}, Channel{channel}, C.GoString(term), int(width), int(height), int(pxwidth), int(pwheight)) {
				return 0
			}
			return 1
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_pty_request_callback(ptr)
}

// SSH channel PTY windows change (terminal size) from a client.
type ChannelChangePtyWindowCallback interface {
	// width	width of the terminal, in characters
	// height	height of the terminal, in characters
	// pxwidth	width of the terminal, in pixels
	// pxheight	height of the terminal, in pixels
	//
	// return true if accepted
	OnChannelChangePtyWindow(session Session, channel Channel, width, height, pxwidth, pwheight int) bool
}

func wrapChannelChangePtyWindowCallback(callback ChannelChangePtyWindowCallback) C.ssh_channel_pty_window_change_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
			if callback.OnChannelChangePtyWindow(Session{session}, Channel{channel}, int(width), int(height), int(pxwidth), int(pwheight)) {
				return 0
			}
			return 1
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_pty_window_change_callback(ptr)
}

// SSH channel Shell request from a client.
type ChanelShellRequestCallback interface {
	// return true if accepted
	OnChannelShellRequest(session Session, channel Channel) bool
}

func wrapChanelShellRequestCallback(callback ChanelShellRequestCallback) C.ssh_channel_shell_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) C.int {
			if callback.OnChannelShellRequest(Session{session}, Channel{channel}) {
				return 0
			}
			return 1
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_shell_request_callback(ptr)
}

// SSH channel signal callback.
//
// Called when a channel has received a signal
type ChannelSignalCallback interface {
	// signal	the signal name (without the SIG prefix)
	OnChannelSignal(session Session, channel Channel, signal string)
}

func wrapChannelSignalCallback(callback ChannelSignalCallback) C.ssh_channel_signal_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, signal *C.char, userdata unsafe.Pointer) {
			callback.OnChannelSignal(Session{session}, Channel{channel}, C.GoString(signal))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_signal_callback(ptr)
}

// SSH channel subsystem request from a client.
type ChannelSubSystemRequestCallback interface {
	// return true if accepted
	OnChannelSubSystemRequest(session Session, channel Channel, subsystem string) bool
}

func wrapChannelSubSystemRequestCallback(callback ChannelSubSystemRequestCallback) C.ssh_channel_subsystem_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, subsystem *C.char, userdata unsafe.Pointer) C.int {
			if callback.OnChannelSubSystemRequest(Session{session}, Channel{channel}, C.GoString(subsystem)) {
				return 0
			}
			return 1
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_subsystem_request_callback(ptr)
}

// SSH X11 request from the client.
//
// This request is sent by a client when X11 forwarding is requested(and
// available). Server is free to ignore this callback, no answer is expected.
type ChannelX11RequestCallback interface {
	OnChannelX11Request(session Session, channel Channel, singleConnection bool, authProtocol, authCookie string, screenNumber int)
}

func wrapChannelX11RequestCallback(callback ChannelX11RequestCallback) C.ssh_channel_x11_req_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, channel C.ssh_channel, single_connection C.int, auth_protocol, auth_cookie *C.char, screen_number C.uint32_t, userdata unsafe.Pointer) {
			callback.OnChannelX11Request(Session{session}, Channel{channel}, single_connection != 0, C.GoString(auth_protocol), C.GoString(auth_cookie), int(screen_number))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_channel_x11_req_callback(ptr)
}

// SSH global request callback.
//
// All global request will go through this callback.
type GlobalRequestCallback interface {
	OnGlobalRequest(session Session, message Message)
}

func wrapGlobalRequestCallback(callback GlobalRequestCallback) C.ssh_global_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, message C.ssh_message, userdata unsafe.Pointer) {
			callback.OnGlobalRequest(Session{session}, Message{message})
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_global_request_callback(ptr)
}

// SSH log callback.
//
// All logging messages will go through this callback
type SessionLogCallback interface {
	OnSessionLog(session Session, priority int, message string)
}

func wrapSessionLogCallback(callback SessionLogCallback) C.ssh_log_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, priority C.int, message *C.char, userdata unsafe.Pointer) {
			callback.OnSessionLog(Session{session}, int(priority), C.GoString(message))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_log_callback(ptr)
}

// All logging messages will go through this callback.
type SshLogCallback interface {
	OnSshLog(priority int, message string)
}

func wrapSshLogCallback(callback SshLogCallback) C.ssh_logging_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(priority C.int, message *C.char, userdata unsafe.Pointer) {
			callback.OnSshLog(int(priority), C.GoString(message))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_logging_callback(ptr)
}

// Prototype for a packet callback, to be called when a new packet arrives
type SessionPacketCallback interface {
	// return true if the packet is parsed
	// return false if the packet needs to continue processing
	OnSessionPacket(session Session, packetType int, buffer Buffer) bool
}

func wrapSessionPacketCallback(callback SessionPacketCallback) C.ssh_packet_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, packetType C.uint8_t, packet C.ssh_buffer, userdata unsafe.Pointer) C.int {
			if callback.OnSessionPacket(Session{session}, int(packetType), Buffer{packet}) {
				return C.SSH_PACKET_USED
			}
			return C.SSH_PACKET_NOT_USED
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_packet_callback(ptr)
}

// Handles an SSH service request.
type SessionServiceRequest interface {
	// return true if allowed
	OnSessionServiceRequest(session Session, service string) bool
}

func wrapSessionServiceRequest(callback SessionServiceRequest) C.ssh_service_request_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, service *C.char, userdata unsafe.Pointer) C.int {
			if callback.OnSessionServiceRequest(Session{session}, C.GoString(service)) {
				return 0
			}
			return -1
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_service_request_callback(ptr)
}

// SSH Connection status callback.
type SessionConnectProgressCallback interface {
	// Percentage of connection status, going from 0.0 to 1.0 once
	// connection is done.
	OnSessionConnectProgress(session Session, percentage float32)
}

func wrapSessionConnectProgressCallback(callback SessionConnectProgressCallback) C.ssh_status_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, status C.float, userdata unsafe.Pointer) {
			callback.OnSessionConnectProgress(Session{session}, float32(status))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_status_callback(ptr)
}

// callbacks define in structs

type ConnectProgressCallback interface {
	OnConnectProgress(percentage float32)
}

func wrapConnectProgressCallback(callback ConnectProgressCallback) C.connect_status_function {
	ptr := NULL
	if callback != nil {
		wrapper := func(userdata unsafe.Pointer, status C.float) {
			callback.OnConnectProgress(float32(status))
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.connect_status_function(ptr)
}

// following is undocumented!

// handle the beginning of a GSSAPI authentication, server side.
type GssapiSelectOidCallback interface {
	OnSessionGssapiSelectOid(session Session, user string, oids []string) string
}

func wrapGssapiSelectOidCallback(callback GssapiSelectOidCallback) C.ssh_gssapi_select_oid_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, user *C.char, n_oids C.int, oids *C.ssh_string, userdata unsafe.Pointer) C.ssh_string {
			oidSlice := make([]string, int(n_oids))
			for i := 0; i < int(n_oids); i++ {
				oid := C.get_oid_by_index(oids, C.int(i))
				oidSlice[i] = SshString{oid}.String()
			}
			selected := callback.OnSessionGssapiSelectOid(Session{session}, C.GoString(user), oidSlice)
			return NewStringFrom(selected).ptr
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_gssapi_select_oid_callback(ptr)
}

// handle the negociation of a security context, server side.
type GssapiAcceptSecurityContextCallback interface {
	// input_token input token provided by client
	// return output of the gssapi accept_sec_context method, NULL after
	// completion.
	OnGssapiAcceptSecurityContext(session Session, inputToken string) (string, bool)
}

func wrapGssapiAcceptSecurityContextCallback(callback GssapiAcceptSecurityContextCallback) C.ssh_gssapi_accept_sec_ctx_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, input_token C.ssh_string, output_token *C.ssh_string, userdata unsafe.Pointer) C.int {
			output, ok := callback.OnGssapiAcceptSecurityContext(Session{session}, SshString{input_token}.String())
			if !ok {
				return SSH_ERROR
			}
			if NewStringFrom(output).Copy(SshString{*output_token}) != nil {
				return SSH_ERROR
			}
			return SSH_OK
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_gssapi_accept_sec_ctx_callback(ptr)
}

type GssapiVerifyMicCallback interface {
	OnGssapiVerifyMic(session Session, mic string, data []byte) error
}

func wrapGssapiVerifyMicCallback(callback GssapiVerifyMicCallback) C.ssh_gssapi_verify_mic_callback {
	ptr := NULL
	if callback != nil {
		wrapper := func(session C.ssh_session, mic C.ssh_string, data_ptr unsafe.Pointer, size C.size_t, userdata unsafe.Pointer) C.int {
			data := copyData(data_ptr, size)
			if callback.OnGssapiVerifyMic(Session{session}, SshString{mic}.String(), data) != nil {
				return SSH_ERROR
			}
			return SSH_OK
		}
		ptr = unsafe.Pointer(&wrapper)
	}
	return C.ssh_gssapi_verify_mic_callback(ptr)
}
