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
import "errors"

// auth-stuff

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
func (s Session) GetAvailableAuthMethodsFromServer() int {
	return int(C.ssh_userauth_list(s.ptr, nil))
}

// Try to do public key authentication with ssh agent.
//
// Note:
// Most server implementations do not permit changing the username during
// authentication. The username should only be set with ssh_options_set() only
// before you connect to the server.
func (s Session) AuthWithUser(name string) error {
	username := CString(name)
	defer username.Free()
	return s.authError(C.ssh_userauth_agent(s.ptr, username.Ptr))
}

// Try to authenticate through the "gssapi-with-mic" method.
func (s Session) AuthWithGassapi() error {
	return s.authError(C.ssh_userauth_gssapi(s.ptr))
}

// Try to authenticate through the "none" method.
func (s Session) AuthWithNone() error {
	return s.authError(C.ssh_userauth_none(s.ptr, nil))
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
func (s Session) AuthWithPassword(password string) error {
	password_cstr := CString(password)
	defer password_cstr.Free()
	return s.authError(C.ssh_userauth_password(s.ptr, nil, password_cstr.Ptr))
}

// Authenticate with public/private key or certificate.
func (s Session) AuthWithPubkey(privateKey Key) error {
	return s.authError(C.ssh_userauth_publickey(s.ptr, nil, privateKey.key))
}

// Tries to automatically authenticate with public key and "none".
//
// It may fail, for instance it doesn't ask for a password and uses a default
// asker for passphrases (in case the private key is encrypted)
//
// passphrase:
// Use this passphrase to unlock the privatekey. Use NULL if you don't want to
// use a passphrase or the user should be asked.
func (s Session) AuthWithPubkeyAutomatically(passphrase string) error {
	var passphrase_cstr *C.char
	if passphrase != "" {
		s := CString(passphrase)
		defer s.Free()
		passphrase_cstr = s.Ptr
	}
	return s.authError(C.ssh_userauth_publickey_auto(s.ptr, nil, passphrase_cstr))
}

// Try to authenticate with the given public key.
//
// To avoid unnecessary processing and user interaction, the following method is
// provided for querying whether authentication using the 'pubkey' would be
// possible
func (s Session) TryAuthWithPubkey(pubkey Key) error {
	return s.authError(C.ssh_userauth_try_publickey(s.ptr, nil, pubkey.key))
}

// Try to authenticate through the "keyboard-interactive" method
func (s Session) AuthWithKeyboardInteractive() error {
	return s.authError(C.ssh_userauth_kbdint(s.ptr, nil, nil))
}

func (s Session) AuthKbdintGetAnswer(answer uint) string {
	return C.GoString(C.ssh_userauth_kbdint_getanswer(s.ptr, C.uint(answer)))
}

func (s Session) AuthKbdintGetInstruction() string {
	return C.GoString(C.ssh_userauth_kbdint_getinstruction(s.ptr))
}

func (s Session) AuthKbdintGetName() string {
	return C.GoString(C.ssh_userauth_kbdint_getname(s.ptr))
}

func (s Session) AuthKbdintGetNAnswers() int {
	return int(C.ssh_userauth_kbdint_getnanswers(s.ptr))
}

func (s Session) AuthKbdintGetNPrompts() int {
	return int(C.ssh_userauth_kbdint_getnprompts(s.ptr))
}

func (s Session) AuthKbdintGetPrompt(i int, echo string) string {
	echo_cstr := CString(echo)
	defer echo_cstr.Free()
	return C.GoString(C.ssh_userauth_kbdint_getprompt(s.ptr, C.uint(i), echo_cstr.Ptr))
}

func (s Session) AuthKbdintSetAnswer(i int, answer string) error {
	answer_cstr := CString(answer)
	defer answer_cstr.Free()
	if C.ssh_userauth_kbdint_setanswer(s.ptr, C.uint(i), answer_cstr.Ptr) < 0 {
		return errors.New("Fails to set auth key")
	}
	return nil
}

func (s Session) authError(err C.int) error {
	switch err {
	case SSH_AUTH_ERROR:
		// SSH_AUTH_ERROR: A serious error happened.
		return &AuthError{}
	case SSH_AUTH_DENIED:
		// SSH_AUTH_DENIED: The server doesn't accept that public key as an
		// authentication token. Try another key or another method.
		return &AuthDenied{}
	case SSH_AUTH_PARTIAL:
		// SSH_AUTH_PARTIAL: You've been partially authenticated, you still have to use
		// another method.
		return &AuthPartial{}
	case SSH_AUTH_AGAIN:
		// SSH_AUTH_AGAIN: In nonblocking mode, you've got to call this again later.
		return &AuthAgain{}
	case SSH_AUTH_SUCCESS:
		// SSH_AUTH_SUCCESS: The public key is accepted, you want now to use
		// ssh_userauth_publickey().
		return nil
	default:
		return &UnknownError{}
	}
}
