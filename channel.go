package libssh

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>

*/
import "C"

type Channel struct {
	ch C.ssh_channel
}
