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
*/
import "C"

func Init() error {
	return apiError("ssh_init", C.ssh_init())
}

func Finalize() error {
	return apiError("ssh_finalize", C.ssh_finalize())
}

func Copyright() string {
	return C.GoString(C.ssh_copyright())
}
