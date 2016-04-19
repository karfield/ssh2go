package libssh

/*
#cgo pkg-config: libssh
#include <libssh/libssh.h>
*/
import "C"

type InternalError struct{}

func (e *InternalError) Error() string { return "Internal error" }

type TryAgainError struct{}

func (e *TryAgainError) Error() string { return "Try again" }

type UnknownError struct{}

func (e *UnknownError) Error() string { return "Unknown error" }

type EOF struct{}

func (e *EOF) Error() string { return "EOF" }

type RequestDenied struct{}

func (e *RequestDenied) Error() string { return "Request denied" }

type UnrecoverableError struct{}

func (e *UnrecoverableError) Error() string { return "Fatal error" }

type IntrruptedError struct{}

func (e *IntrruptedError) Error() string { return "Interrupted error" }

type AuthError struct{}

func (e *AuthError) Error() string { return "Authenticate error" }

type AuthDenied struct{}

func (e *AuthDenied) Error() string { return "Authenticate denied" }

type AuthPartial struct{}

func (e *AuthPartial) Error() string { return "Partially authenticated" }

type AuthAgain struct{}

func (e *AuthAgain) Error() string { return "Authenicated again" }
