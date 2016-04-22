package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>
*/
import "C"

func authError(fn string, r C.int) (int, error) {
	ret := int(r)
	switch ret {
	case SSH_AUTH_SUCCESS,
		SSH_AUTH_DENIED,
		SSH_AUTH_PARTIAL,
		SSH_AUTH_INFO,
		SSH_AUTH_AGAIN:
		return ret, nil
	default:
		if ret < 0 {
			return ret, apiError(fn, ret)
		}
		return ret, apiError(fn, -1)
	}
}

// Get available authentication methods from the server.
// This requires the function ssh_userauth_none() to be called before the methods
// are available. The server MAY return a list of methods that may continue.
//
// Returns
//  A bitfield of the fllowing values:
//  SSH_AUTH_METHOD_PASSWORD
//  SSH_AUTH_METHOD_PUBLICKEY
//  SSH_AUTH_METHOD_HOSTBASED
//  SSH_AUTH_METHOD_INTERACTIVE
func (s Session) UserAuthList() int {
	return int(C.ssh_userauth_list(s.ptr, nil))
}

// Try to do public key authentication with ssh agent.
//
// Note:
// Most server implementations do not permit changing the username during
// authentication. The username should only be set with ssh_options_set() only
// before you connect to the server.
//
// returns:
//  state int:
//
func (s Session) UserAuthAgent(name string) (int, error) {
	return authError("ssh_userauth_agent", C.ssh_userauth_agent(s.ptr, nil))
}

// Try to authenticate through the "gssapi-with-mic" method.
func (s Session) UserAuthGssapi() (int, error) {
	return authError("ssh_userauth_gssapi", C.ssh_userauth_gssapi(s.ptr))
}

// Try to authenticate through the "none" method.
func (s Session) UserAuthNone() (int, error) {
	return authError("ssh_userauth_none", C.ssh_userauth_none(s.ptr, nil))
}

// Try to authenticate by password
//
// This authentication method is normally disabled on SSHv2 server. You should
// use keyboard-interactive mode.
//
// The 'password' value MUST be encoded UTF-8. It is up to the server how to
// interpret the password and validate it against the password database.
// However, if you read the password in some other encoding, you MUST convert
// the password to UTF-8.
//
func (s Session) UseAuthPassword(password string) (int, error) {
	password_cstr := CString(password)
	defer password_cstr.Free()
	return authError("ssh_userauth_password", C.ssh_userauth_password(s.ptr, nil, password_cstr.Ptr))
}

// Authenticate with public/private key or certificate.
func (s Session) UserAuthPublicKey(privateKey Key) (int, error) {
	return authError("ssh_userauth_try_publickey", C.ssh_userauth_publickey(s.ptr, nil, privateKey.key))
}

// Tries to automatically authenticate with public key and "none".
//
// It may fail, for instance it doesn't ask for a password and uses a default
// asker for passphrases (in case the private key is encrypted)
//
// passphrase:
// Use this passphrase to unlock the privatekey. Use NULL if you don't want to
// use a passphrase or the user should be asked.
func (s Session) UserAuthPublicKeyAuto(passphrase string) (int, error) {
	var passphrase_cstr *C.char
	if passphrase != "" {
		s := CString(passphrase)
		defer s.Free()
		passphrase_cstr = s.Ptr
	}
	return authError("ssh_userauth_publickey_auto", C.ssh_userauth_publickey_auto(s.ptr, nil, passphrase_cstr))
}

// Try to authenticate with the given public key.
//
// To avoid unnecessary processing and user interaction, the following method is
// provided for querying whether authentication using the 'pubkey' would be
// possible
func (s Session) UserAuthTryPublickKey(pubkey Key) (int, error) {
	return authError("ssh_userauth_try_publickey", C.ssh_userauth_try_publickey(s.ptr, nil, pubkey.key))
}

// Try to authenticate through the "keyboard-interactive" method
func (s Session) UserAuthKeybdInteractive() (int, error) {
	return authError("ssh_userauth_kbdint", C.ssh_userauth_kbdint(s.ptr, nil, nil))
}

func (s Session) UserAuthKeybdGetAnswer(n uint) (string, error) {
	answer := C.ssh_userauth_kbdint_getanswer(s.ptr, C.uint(n))
	if answer == nil {
		return "", apiError("ssh_userauth_kbdint_getanswer", "NULL")
	}
	return C.GoString(answer), nil
}

func (s Session) UserAuthKeybdGetInstruction() (string, error) {
	inst := C.ssh_userauth_kbdint_getinstruction(s.ptr)
	if inst == nil {
		return "", apiError("ssh_userauth_kbdint_getinstruction", "NULL")
	}
	return C.GoString(inst), nil
}

func (s Session) UserAuthKeybdGetName() (string, error) {
	name := C.ssh_userauth_kbdint_getname(s.ptr)
	if name == nil {
		return "", apiError("ssh_userauth_kbdint_getname", "NULL")
	}
	return C.GoString(name), nil
}

func (s Session) UserAuthKeybdGetNAnswers() (int, error) {
	n := int(C.ssh_userauth_kbdint_getnanswers(s.ptr))
	if n < 0 {
		return n, apiError("ssh_userauth_kbdint_getnanswers", n)
	}
	return int(n), nil
}

func (s Session) UserAuthKeybdGetNPrompts() (int, error) {
	n := int(C.ssh_userauth_kbdint_getnprompts(s.ptr))
	if n < 0 {
		return n, apiError("ssh_userauth_kbdint_getnprompts", n)
	}
	return int(n), nil
}

func (s Session) UserAuthKeybdGetPrompt(i int, echo string) (string, error) {
	echo_cstr := CString(echo)
	defer echo_cstr.Free()
	prompt := C.ssh_userauth_kbdint_getprompt(s.ptr, C.uint(i), echo_cstr.Ptr)
	if prompt == nil {
		return "", apiError("ssh_userauth_kbdint_getprompt", "NULL")
	}
	return C.GoString(prompt), nil
}

func (s Session) AuthKbdintSetAnswer(i int, answer string) error {
	answer_cstr := CString(answer)
	defer answer_cstr.Free()
	return apiError("ssh_userauth_kbdint_setanswer",
		C.ssh_userauth_kbdint_setanswer(s.ptr, C.uint(i), answer_cstr.Ptr))
}
