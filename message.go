package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

char ** make_c_string_array(int length) {
	return (char **)malloc(sizeof(char *)*length);
}

void append_c_string_array(char **array, int index, char * data) {
	array[index] = data;
}

*/
import "C"
import (
	"errors"
	"unsafe"
)

type Message struct {
	msg C.ssh_message
}

func (s *Session) RetrieveMessage() (Message, error) {
	msg := C.ssh_message_get(s.ptr)
	if msg != nil {
		return Message{msg}, nil
	}
	return Message{}, errors.New("ssh_message_get() == nil")
}

func (m Message) Free() {
	C.ssh_message_free(m.msg)
}

func (m Message) Type() int {
	return int(C.ssh_message_type(m.msg))
}

func (m Message) SubType() int {
	return int(C.ssh_message_subtype(m.msg))
}

// SERVER MESSAGING

// Reply with a standard reject message.
//
// Use this function if you don't know what to respond or if you want to reject
// a request.
func (m Message) ReplyDefault() error {
	return apiError("ssh_message_reply_default",
		C.ssh_message_reply_default(m.msg))
}

func (m Message) AuthUser() (string, error) {
	user := C.ssh_message_auth_user(m.msg)
	if user == nil {
		return "", apiError("ssh_message_auth_user", "NULL")
	}
	return C.GoString(user), nil
}

func (m Message) AuthPassword() (string, error) {
	password := C.ssh_message_auth_password(m.msg)
	if password == nil {
		return "", apiError("ssh_message_auth_password", "NULL")
	}
	return C.GoString(password), nil
}

func (m Message) AuthPublicKey() (Key, error) {
	key := C.ssh_message_auth_pubkey(m.msg)
	if key == nil {
		return Key{}, apiError("ssh_message_auth_pubkey", "NULL")
	}
	return Key{key}, nil
}

func (m Message) AuthKeybdIsResponsed() (bool, error) {
	if r := C.ssh_message_auth_kbdint_is_response(m.msg); r < 0 {
		return false, apiError("message_auth_kbdint_is_response", r)
	} else {
		return r != 0, nil
	}
}

func (m Message) AuthPublicKeyState() (int, error) {
	state := C.ssh_message_auth_publickey_state(m.msg)
	return int(state), apiError("ssh_message_auth_publickey_state", int(state))
}

func (m Message) AuthReplySuccess(partial bool) error {
	return apiError("ssh_message_auth_reply_success",
		C.ssh_message_auth_reply_success(m.msg, CBool(partial)))
}

// Answer OK to a pubkey auth request
func (m Message) AuthReplyPubkeyOkay(algo, publickKey SshString) error {
	return apiError("ssh_message_auth_reply_pk_ok",
		C.ssh_message_auth_reply_pk_ok(m.msg, algo.ptr, publickKey.ptr))
}

func (m Message) AuthReplyPubkeyOkaySimple() error {
	return apiError("ssh_message_auth_reply_pk_ok_simple",
		C.ssh_message_auth_reply_pk_ok_simple(m.msg))
}

func (m Message) AuthSetMethods(methods int) error {
	return apiError("ssh_message_auth_set_methods",
		C.ssh_message_auth_set_methods(m.msg, C.int(methods)))
}

func (m Message) AuthInteractiveRequest(name, instruction string, prompts []string, echo string) error {
	prompt_array := C.make_c_string_array(C.int(len(prompts)))
	if prompt_array == nil {
		return apiError("malloc", "NULL")
	}
	defer C.free(unsafe.Pointer(prompt_array))
	for i, p := range prompts {
		prompt := CString(p)
		defer prompt.Free()
		C.append_c_string_array(prompt_array, C.int(i), prompt.Ptr)
	}
	name_cstr := CString(name)
	defer name_cstr.Free()
	instruction_cstr := CString(instruction)
	defer instruction_cstr.Free()
	echo_cstr := CString(echo)
	defer echo_cstr.Free()
	return apiError("ssh_message_auth_interactive_request",
		C.ssh_message_auth_interactive_request(m.msg, name_cstr.Ptr, instruction_cstr.Ptr,
			C.uint(len(prompts)), prompt_array, echo_cstr.Ptr))
}

func (m Message) ServiceReplySuccess() error {
	return apiError("ssh_message_service_reply_success",
		C.ssh_message_service_reply_success(m.msg))
}

func (m Message) ServiceName() (string, error) {
	name := C.ssh_message_service_service(m.msg)
	if name == nil {
		return "", apiError("ssh_message_service_service", "NULL")
	}
	return C.GoString(name), nil
}

func (m Message) GlobalRequestReplySuccess(boundPort int) error {
	return apiError("ssh_message_global_request_reply_success",
		C.ssh_message_global_request_reply_success(m.msg, C.uint16_t(boundPort)))
}

func (m Message) ChannelRequestOpenOriginator() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_open_originator",
		C.ssh_message_channel_request_open_originator(m.msg))
}

func (m Message) ChannelRequestOpenOriginatorPort() (int, error) {
	port := C.ssh_message_channel_request_open_originator_port(m.msg)
	if port > 0 {
		return int(port), nil
	}
	return -1, apiError("ssh_message_channel_request_open_originator_port", port)
}

func (m Message) ChannelRequestOpenDestination() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_open_destination",
		C.ssh_message_channel_request_open_destination(m.msg))
}

func (m Message) ChannelRequestOpenDestinationPort() (int, error) {
	port := C.ssh_message_channel_request_open_destination_port(m.msg)
	if port > 0 {
		return int(port), nil
	}
	return -1, apiError("ssh_message_channel_request_open_destination_port", port)
}

func (m Message) ChannelRequestChannel() (Channel, error) {
	ch := C.ssh_message_channel_request_channel(m.msg)
	if ch == nil {
		return Channel{}, apiError("ssh_message_channel_request_channel", "NULL")
	}
	return Channel{ch}, nil
}

func (m Message) ChannelRequestPtyTerminal() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_pty_term",
		C.ssh_message_channel_request_pty_term(m.msg))
}

func (m Message) ChanRequestPtyWidth() (int, error) {
	width := C.ssh_message_channel_request_pty_width(m.msg)
	return int(width), apiError("ssh_message_channel_request_pty_width", width)
}

func (m Message) ChanRequestPtyHeight() (int, error) {
	height := C.ssh_message_channel_request_pty_height(m.msg)
	return int(height), apiError("ssh_message_channel_request_pty_height", height)
}

func (m Message) ChanRequestPtyPixelWidth() (int, error) {
	width := C.ssh_message_channel_request_pty_pxwidth(m.msg)
	return int(width), apiError("ssh_message_channel_request_pty_pxwidth", width)
}

func (m Message) ChanRequestPtyPixelHeight() (int, error) {
	height := C.ssh_message_channel_request_pty_pxheight(m.msg)
	return int(height), apiError("ssh_message_channel_request_pty_pxheight", height)
}

func (m Message) ChannelRequestEnvName() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_env_name",
		C.ssh_message_channel_request_env_name(m.msg))
}
func (m Message) ChannelRequestEnvValue() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_env_value",
		C.ssh_message_channel_request_env_value(m.msg))
}

func (m Message) ChannelRequestCommand() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_command",
		C.ssh_message_channel_request_command(m.msg))
}

func (m Message) ChannelRequestSubSystem() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_subsystem",
		C.ssh_message_channel_request_subsystem(m.msg))
}

func (m Message) ChannelRequestX11SingleConnection() (bool, error) {
	ret := C.ssh_message_channel_request_x11_single_connection(m.msg)
	return ret != 0, apiError("ssh_message_channel_request_x11_single_connection", ret)
}

func (m Message) ChannelRequestX11AuthProtocol() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_x11_auth_protocol",
		C.ssh_message_channel_request_x11_auth_protocol(m.msg))
}

func (m Message) ChannelRequestX11AuthCookie() (string, error) {
	return apiErrorWithNullString("ssh_message_channel_request_x11_auth_cookie",
		C.ssh_message_channel_request_x11_auth_cookie(m.msg))
}

func (m Message) ChannelRequestX11ScreenNumber() (int, error) {
	number := C.ssh_message_channel_request_x11_screen_number(m.msg)
	if number < 0 {
		return -1, apiError("ssh_message_channel_request_x11_screen_number", number)
	}
	return int(number), nil
}

func (m Message) GlobalRequestAddress() (string, error) {
	return apiErrorWithNullString("ssh_message_global_request_address",
		C.ssh_message_global_request_address(m.msg))
}

func (m Message) GlobalRequestPort() (int, error) {
	port := C.ssh_message_global_request_port(m.msg)
	if port <= 0 {
		return -1, apiError("ssh_message_global_request_port", port)
	}
	return int(port), nil
}
