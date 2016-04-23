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
extern ssh_callbacks new_callbacks(int userdata);
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
extern ssh_channel_callbacks new_channel_callbacks(int userdata);
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
extern ssh_server_callbacks new_server_callbacks(int userdata);
extern int set_server_callbacks(ssh_session session, ssh_server_callbacks callbacks);

*/
import "C"

import (
	"reflect"
	"runtime"
	"unsafe"
)

var NULL = unsafe.Pointer(nil)
var callbackCache = map[int]interface{}{}
var callbackIndexer = 0

func addCallback(intf interface{}) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	callbackCache[callbackIndexer] = intf
	defer func() {
		callbackIndexer++
	}()
	return callbackIndexer
}

func getCallback(userdata unsafe.Pointer) interface{} {
	index := int(C.pointer_to_int(userdata))
	return callbackCache[index]
}

func removeCallback(index int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	delete(callbackCache, index)
}

type SessionCallbacks struct {
	callbacks C.ssh_callbacks
}

func (s Session) SetCallbacks(impls interface{}) (SessionCallbacks, error) {
	index := addCallback(impls)
	callbacks := C.new_callbacks(C.int(index))
	if _, ok := impls.(SshAuthCallback); ok {
		C.install_auth_callback(callbacks)
	}
	if _, ok := impls.(SessionLogCallback); ok {
		C.install_log_callback(callbacks)
	}
	if _, ok := impls.(ConnectProgressCallback); ok {
		C.install_connection_status_callback(callbacks)
	}
	if _, ok := impls.(GlobalRequestCallback); ok {
		C.install_global_request_callback(callbacks)
	}
	/*if _, ok := impls.(SessionConnectProgressCallback); ok {
		C.install_connection_status_callback(callbacks)
	}*/
	if _, ok := impls.(OpenX11Callback); ok {
		C.install_channel_open_request_x11_callback(callbacks)
	}
	if _, ok := impls.(OpenAuthAgentCallbak); ok {
		C.install_channel_open_request_auth_agent_callback(callbacks)
	}
	err := apiError("ssh_set_callbacks", C.set_callbacks(s.ptr, callbacks))
	if err != nil {
		removeCallback(index)
	}
	return SessionCallbacks{callbacks}, err
}

func (cbs SessionCallbacks) Free() {
	C.free(unsafe.Pointer(cbs.callbacks))
}

type ChannelCallbacks struct {
	callbacks C.ssh_channel_callbacks
}

var channelCallbacks = []interface{}{}

func (c Channel) SetCallbacks(impls interface{}) (ChannelCallbacks, error) {
	index := addCallback(impls)
	callbacks := C.new_channel_callbacks(C.int(index))
	if _, ok := impls.(ChannelRawDataCallback); ok {
		C.install_channel_data_callback(callbacks)
	} else if _, ok = impls.(ChannelDataCallback); ok {
		C.install_channel_data_callback(callbacks)
	}
	if _, ok := impls.(ChannelEofCallback); ok {
		C.install_channel_eof_callback(callbacks)
	}
	if _, ok := impls.(ChannelCloseCallback); ok {
		C.install_channel_close_callback(callbacks)
	}
	if _, ok := impls.(ChannelSignalCallback); ok {
		C.install_channel_signal_callback(callbacks)
	}
	if _, ok := impls.(ChannelExitStatusCallback); ok {
		C.install_channel_exit_status_callback(callbacks)
	}
	if _, ok := impls.(ChannelExitSignalCallback); ok {
		C.install_channel_exit_signal_callback(callbacks)
	}
	if _, ok := impls.(ChannelNewPtyRequestCallback); ok {
		C.install_channel_pty_request_callback(callbacks)
	}
	if _, ok := impls.(ChannelShellRequestCallback); ok {
		C.install_channel_shell_request_callback(callbacks)
	}
	if _, ok := impls.(AuthAgentRequestCallback); ok {
		C.install_channel_auth_agent_req_callback(callbacks)
	}
	if _, ok := impls.(ChannelX11RequestCallback); ok {
		C.install_channel_x11_req_callback(callbacks)
	}
	if _, ok := impls.(ChannelChangePtyWindowCallback); ok {
		C.install_channel_pty_window_change_callback(callbacks)
	}
	if _, ok := impls.(ChannelExecRequestCallback); ok {
		C.install_channel_exec_request_callback(callbacks)
	}
	if _, ok := impls.(ChannelEnvRequestCallback); ok {
		C.install_channel_env_request_callback(callbacks)
	}
	if _, ok := impls.(ChannelSubSystemRequestCallback); ok {
		C.install_channel_subsystem_request_callback(callbacks)
	}
	err := apiError("ssh_set_channel_callbacks", C.set_channel_callbacks(c.ptr, callbacks))
	if err != nil {
		removeCallback(index)
	}
	return ChannelCallbacks{callbacks}, err
}

func (cbs ChannelCallbacks) Free() {
	C.free(unsafe.Pointer(cbs.callbacks))
}

type ServerCallbacks struct {
	callbacks C.ssh_server_callbacks
}

var serverCallbacks = []interface{}{}

func (s Session) SetServerCallbacks(impls interface{}) (ServerCallbacks, error) {
	index := addCallback(impls)
	callbacks := C.new_server_callbacks(C.int(index))
	if _, ok := impls.(AuthPasswordCallback); ok {
		C.install_auth_password_callback(callbacks)
	}
	if _, ok := impls.(AuthNoneCallback); ok {
		C.install_auth_none_callback(callbacks)
	}
	if _, ok := impls.(AuthGssapiMicCallback); ok {
		C.install_auth_gssapi_mic_callback(callbacks)
	}
	if _, ok := impls.(AuthPublicKeyCallback); ok {
		C.install_auth_pubkey_callback(callbacks)
	}
	if _, ok := impls.(SessionServiceRequest); ok {
		C.install_service_request_callback(callbacks)
	}
	if _, ok := impls.(OpenChannelCallback); ok {
		C.install_channel_open_request_session_callback(callbacks)
	}
	if _, ok := impls.(GssapiSelectOidCallback); ok {
		C.install_gssapi_select_oid_callback(callbacks)
	}
	if _, ok := impls.(GssapiAcceptSecurityContextCallback); ok {
		C.install_gssapi_accept_sec_ctx_callback(callbacks)
	}
	if _, ok := impls.(GssapiVerifyMicCallback); ok {
		C.install_gssapi_verify_mic_callback(callbacks)
	}
	err := apiError("ssh_set_server_callbacks", C.set_server_callbacks(s.ptr, callbacks))
	if err != nil {
		removeCallback(index)
	}
	return ServerCallbacks{callbacks}, err
}

func (cbs ServerCallbacks) Free() {
	C.free(unsafe.Pointer(cbs.callbacks))
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

//export auth_callback
func auth_callback(prompt C.conststr, buf *C.char, length C.size_t, echo C.int, verify C.int, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(SshAuthCallback)
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

//export auth_gssapi_mic_callback
func auth_gssapi_mic_callback(session C.ssh_session, user, principle C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(AuthGssapiMicCallback)
	return C.int(callback.OnSshAuthGssapiMic(Session{session}, C.GoString(user), C.GoString(principle)))
}

// handle the beginning of a GSSAPI authentication, server side.
type GssapiSelectOidCallback interface {
	OnSessionGssapiSelectOid(session Session, user string, oids []string) string
}

//export gssapi_select_oid_callback
func gssapi_select_oid_callback(session C.ssh_session, user C.conststr, n_oids C.int, oids *C.ssh_string, userdata unsafe.Pointer) C.ssh_string {
	callback, _ := getCallback(userdata).(GssapiSelectOidCallback)
	oidSlice := make([]string, int(n_oids))
	for i := 0; i < int(n_oids); i++ {
		oid := C.get_oid_by_index(oids, C.int(i))
		oidSlice[i] = SshString{oid}.String()
	}
	selected := callback.OnSessionGssapiSelectOid(Session{session}, C.GoString(user), oidSlice)
	return NewStringFrom(selected).ptr
}

// handle the negociation of a security context, server side.
type GssapiAcceptSecurityContextCallback interface {
	// input_token input token provided by client
	// return output of the gssapi accept_sec_context method, NULL after
	// completion.
	OnGssapiAcceptSecurityContext(session Session, inputToken string) (string, bool)
}

//export gssapi_accept_sec_ctx_callback
func gssapi_accept_sec_ctx_callback(session C.ssh_session, input_token C.ssh_string, output_token *C.ssh_string, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(GssapiAcceptSecurityContextCallback)
	outputToken, accepted := callback.OnGssapiAcceptSecurityContext(Session{session}, SshString{input_token}.String())
	if accepted {
		if err := NewStringFrom(outputToken).Copy(SshString{*output_token}); err == nil {
			return SSH_OK
		}
	}
	return SSH_ERROR
}

type GssapiVerifyMicCallback interface {
	OnGssapiVerifyMic(session Session, mic string, data []byte) error
}

//export gssapi_verify_mic_callback
func gssapi_verify_mic_callback(session C.ssh_session, mic C.ssh_string, data_ptr unsafe.Pointer, size C.size_t, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(GssapiVerifyMicCallback)
	data := copyData(data_ptr, size)
	if callback.OnGssapiVerifyMic(Session{session}, SshString{mic}.String(), data) != nil {
		return SSH_ERROR
	}
	return SSH_OK
}

// Tries to authenticates user with the "none" method which is anonymous or
// passwordless.
type AuthNoneCallback interface {
	OnAuthNone(session Session, user string) int
}

//export auth_none_callback
func auth_none_callback(session C.ssh_session, user C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(AuthNoneCallback)
	return C.int(callback.OnAuthNone(Session{session}, C.GoString(user)))
}

// Tries to authenticates user with password
type AuthPasswordCallback interface {
	OnAuthPassword(session Session, user, password string) int
}

var authPasswordCallbackType = reflect.TypeOf(AuthPasswordCallback(nil))

//export auth_password_callback
func auth_password_callback(session C.ssh_session, user, password C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(AuthPasswordCallback)
	return C.int(callback.OnAuthPassword(Session{session}, C.GoString(user), C.GoString(password)))
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

//export auth_pubkey_callback
func auth_pubkey_callback(session C.ssh_session, user C.conststr, pubkey *C.struct_ssh_key_struct,
	signature_state C.char, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(AuthPublicKeyCallback)
	return C.int(callback.OnAuthPublickKey(Session{session}, C.GoString(user), Key{pubkey}, int(signature_state)))
}

// SSH auth-agent-request from the client.
//
// This request is sent by a client when agent forwarding is available. Server
// is free to ignore this callback, no answer is expected.
type AuthAgentRequestCallback interface {
	OnChannelAuthAgentRequest(session Session, channel Channel)
}

//export channel_auth_agent_req_callback
func channel_auth_agent_req_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(AuthAgentRequestCallback)
	callback.OnChannelAuthAgentRequest(Session{session}, Channel{channel})
}

// SSH channel close callback.
//
// Called when a channel is closed by remote peer
type ChannelCloseCallback interface {
	OnChannelClose(session Session, channel Channel)
}

//export channel_close_callback
func channel_close_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelCloseCallback)
	callback.OnChannelClose(Session{session}, Channel{channel})
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
	ptr := getCallback(userdata)
	if rawProcess, ok := ptr.(ChannelRawDataCallback); ok {
		return C.int(rawProcess.OnChannelRawData(Session{session}, Channel{channel}, data_ptr, uint(len), is_stderr != 0))
	} else if process, ok := ptr.(ChannelDataCallback); ok {
		return C.int(process.OnChannelData(Session{session}, Channel{channel}, copyData(data_ptr, len), is_stderr != 0))
	}
	return SSH_ERROR
}

// SSH channel environment request from a client.
type ChannelEnvRequestCallback interface {
	// return true if env request accepted
	OnChannelEnvRequest(session Session, channel Channel, envName, envValue string) bool
}

//export channel_env_request_callback
func channel_env_request_callback(session C.ssh_session, channel C.ssh_channel,
	env_name, env_value C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelEnvRequestCallback)
	if callback.OnChannelEnvRequest(Session{session}, Channel{channel}, C.GoString(env_name), C.GoString(env_value)) {
		// 0 if the env request is accepted
		return 0
	} else {
		// 1 if the request is denied
		return 1
	}
}

// SSH channel eof callback.
//
// Called when a channel receives EOF
type ChannelEofCallback interface {
	OnChannelEOF(session Session, channel Channel)
}

//export channel_eof_callback
func channel_eof_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelEofCallback)
	callback.OnChannelEOF(Session{session}, Channel{channel})
}

// SSH channel Exec request from a client.
type ChannelExecRequestCallback interface {
	// return true if the request accepted
	OnChannelExecRequest(session Session, channel Channel, cmdline string) bool
}

//export channel_exec_request_callback
func channel_exec_request_callback(session C.ssh_session, channel C.ssh_channel,
	cmdline C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelExecRequestCallback)
	if callback.OnChannelExecRequest(Session{session}, Channel{channel}, C.GoString(cmdline)) {
		return 0
	} else {
		return 1
	}
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

//export channel_exit_signal_callback
func channel_exit_signal_callback(session C.ssh_session, channel C.ssh_channel,
	signal C.conststr, core C.int, errmsg, lang C.conststr, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelExitSignalCallback)
	callback.OnChannelExitSignal(Session{session}, Channel{channel}, C.GoString(signal), core != 0, C.GoString(errmsg), C.GoString(lang))
}

// SSH channel exit status callback.
//
// Called when a channel has received an exit status
type ChannelExitStatusCallback interface {
	OnChannelExitStatus(session Session, channel Channel, status int)
}

//export channel_exit_status_callback
func channel_exit_status_callback(session C.ssh_session, channel C.ssh_channel, status C.int, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelExitStatusCallback)
	callback.OnChannelExitStatus(Session{session}, Channel{channel}, int(status))
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

//export channel_open_request_auth_agent_callback
func channel_open_request_auth_agent_callback(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
	callback, _ := getCallback(userdata).(OpenAuthAgentCallbak)
	return callback.OnOpenAuthAgent(Session{session}).ptr
}

// Handles an SSH new channel open session request.
//
// Warning:
//  The channel pointer returned by this callback must be closed by the
//  application.
type OpenChannelCallback interface {
	OnOpenChannel(session Session) Channel
}

//export channel_open_request_session_callback
func channel_open_request_session_callback(session C.ssh_session, userdata unsafe.Pointer) C.ssh_channel {
	callback, _ := getCallback(userdata).(OpenChannelCallback)
	return callback.OnOpenChannel(Session{session}).ptr
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

//export channel_open_request_x11_callback
func channel_open_request_x11_callback(session C.ssh_session, originator_address C.conststr, originator_port C.int, userdata unsafe.Pointer) C.ssh_channel {
	callback, _ := getCallback(userdata).(OpenX11Callback)
	return callback.OnOpenX11(Session{session}, C.GoString(originator_address), int(originator_port)).ptr
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

//export channel_pty_request_callback
func channel_pty_request_callback(session C.ssh_session, channel C.ssh_channel,
	term C.conststr, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelNewPtyRequestCallback)
	if callback.OnChannelNewPty(Session{session}, Channel{channel}, C.GoString(term), int(width), int(height), int(pxwidth), int(pwheight)) {
		return 0
	}
	return 1
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

//export channel_pty_window_change_callback
func channel_pty_window_change_callback(session C.ssh_session, channel C.ssh_channel, width, height, pxwidth, pwheight C.int, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelChangePtyWindowCallback)
	if callback.OnChannelChangePtyWindow(Session{session}, Channel{channel}, int(width), int(height), int(pxwidth), int(pwheight)) {
		return 0
	}
	return 1
}

// SSH channel Shell request from a client.
type ChannelShellRequestCallback interface {
	// return true if accepted
	OnChannelShellRequest(session Session, channel Channel) bool
}

//export channel_shell_request_callback
func channel_shell_request_callback(session C.ssh_session, channel C.ssh_channel, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelShellRequestCallback)
	if callback.OnChannelShellRequest(Session{session}, Channel{channel}) {
		return 0
	}
	return 1
}

// SSH channel signal callback.
//
// Called when a channel has received a signal
type ChannelSignalCallback interface {
	// signal	the signal name (without the SIG prefix)
	OnChannelSignal(session Session, channel Channel, signal string)
}

//export channel_signal_callback
func channel_signal_callback(session C.ssh_session, channel C.ssh_channel, signal C.conststr, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelSignalCallback)
	callback.OnChannelSignal(Session{session}, Channel{channel}, C.GoString(signal))
}

// SSH channel subsystem request from a client.
type ChannelSubSystemRequestCallback interface {
	// return true if accepted
	OnChannelSubSystemRequest(session Session, channel Channel, subsystem string) bool
}

//export channel_subsystem_request_callback
func channel_subsystem_request_callback(session C.ssh_session, channel C.ssh_channel,
	subsystem C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(ChannelSubSystemRequestCallback)
	if callback.OnChannelSubSystemRequest(Session{session}, Channel{channel}, C.GoString(subsystem)) {
		return 0
	}
	return 1
}

// SSH X11 request from the client.
//
// This request is sent by a client when X11 forwarding is requested(and
// available). Server is free to ignore this callback, no answer is expected.
type ChannelX11RequestCallback interface {
	OnChannelX11Request(session Session, channel Channel, singleConnection bool, authProtocol, authCookie string, screenNumber int)
}

//export channel_x11_req_callback
func channel_x11_req_callback(session C.ssh_session, channel C.ssh_channel,
	single_connection C.int, auth_protocol, auth_cookie C.conststr,
	screen_number C.uint32_t, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(ChannelX11RequestCallback)
	callback.OnChannelX11Request(Session{session}, Channel{channel}, single_connection != 0, C.GoString(auth_protocol), C.GoString(auth_cookie), int(screen_number))
}

// SSH global request callback.
//
// All global request will go through this callback.
type GlobalRequestCallback interface {
	OnGlobalRequest(session Session, message Message)
}

//export global_request_callback
func global_request_callback(session C.ssh_session, message C.ssh_message, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(GlobalRequestCallback)
	callback.OnGlobalRequest(Session{session}, Message{message})
}

// SSH log callback.
//
// All logging messages will go through this callback
type SessionLogCallback interface {
	OnSessionLog(session Session, priority int, message string)
}

//export session_log_callback
func session_log_callback(session C.ssh_session, priority C.int, message C.conststr, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(SessionLogCallback)
	callback.OnSessionLog(Session{session}, int(priority), C.GoString(message))
}

// Prototype for a packet callback, to be called when a new packet arrives
type SessionPacketCallback interface {
	// return true if the packet is parsed
	// return false if the packet needs to continue processing
	OnSessionPacket(session Session, packetType int, buffer Buffer) bool
}

//export packet_callback
func packet_callback(session C.ssh_session, packetType C.uint8_t, packet C.ssh_buffer, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(SessionPacketCallback)
	if callback.OnSessionPacket(Session{session}, int(packetType), Buffer{packet}) {
		return C.SSH_PACKET_USED
	}
	return C.SSH_PACKET_NOT_USED
}

// Handles an SSH service request.
type SessionServiceRequest interface {
	// return true if allowed
	OnSessionServiceRequest(session Session, service string) bool
}

//export service_request_callback
func service_request_callback(session C.ssh_session, service C.conststr, userdata unsafe.Pointer) C.int {
	callback, _ := getCallback(userdata).(SessionServiceRequest)
	if callback.OnSessionServiceRequest(Session{session}, C.GoString(service)) {
		return 0
	}
	return -1
}

// SSH Connection status callback.
type SessionConnectProgressCallback interface {
	// Percentage of connection status, going from 0.0 to 1.0 once
	// connection is done.
	OnSessionConnectProgress(session Session, percentage float32)
}

//export status_callback
func status_callback(session C.ssh_session, status C.float, userdata unsafe.Pointer) {
	callback, _ := getCallback(userdata).(SessionConnectProgressCallback)
	callback.OnSessionConnectProgress(Session{session}, float32(status))
}

// callbacks define in structs

type ConnectProgressCallback interface {
	OnConnectProgress(percentage float32)
}

//export connection_status_callback
func connection_status_callback(userdata unsafe.Pointer, status C.float) {
	callback, _ := getCallback(userdata).(ConnectProgressCallback)
	callback.OnConnectProgress(float32(status))
}
