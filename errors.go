package libssh

/*
#include <libssh/libssh.h>
*/
import "C"

type TryAgainError struct{}

func (e *TryAgainError) Error() string { return "Try again" }

type UnknownError struct{}

func (e *UnknownError) Error() string { return "Unknown error" }

func commonError(ret C.int) error {
	switch ret {
	case SSH_OK:
		return nil
	case SSH_AGAIN:
		return &TryAgainError{}
	default:
		return &UnknownError{}
	}
}

type AuthError struct{}

func (e *AuthError) Error() string { return "Authenticate error" }

type AuthDenied struct{}

func (e *AuthDenied) Error() string { return "Authenticate denied" }

type AuthPartial struct{}

func (e *AuthPartial) Error() string { return "Partially authenticated" }

type AuthAgain struct{}

func (e *AuthAgain) Error() string { return "Authenicated again" }

func authError(err C.int) error {
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
