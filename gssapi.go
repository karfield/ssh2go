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

type GssapiCreds struct {
	creds C.ssh_gssapi_creds
}

func (s Session) GssapiGetCreds() (GssapiCreds, error) {
	creds := C.ssh_gssapi_get_creds(s.ptr)
	if creds == nil {
		return GssapiCreds{}, apiError("ssh_gssapi_get_creds", "NULL")
	}
	return GssapiCreds{creds}, nil
}
