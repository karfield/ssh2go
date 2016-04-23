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

typedef const char *conststr;
extern int set_log_callback();
*/
import "C"
import "unsafe"

func SetLogLevel(level int) {
	C.ssh_set_log_level(C.int(level))
}

func GetLogLevel() int {
	return int(C.ssh_get_log_level())
}

type LoggingCallback interface {
	OnLogging(priority int, fnname string, message string)
}

var loggingCallback LoggingCallback = nil

//export logging_callback
func logging_callback(priority C.int, function, buffer C.conststr, userdata unsafe.Pointer) {
	if loggingCallback != nil {
		loggingCallback.OnLogging(int(priority), C.GoString(function), C.GoString(buffer))
	}
}

func SetLoggingCallback(callback LoggingCallback) error {
	loggingCallback = callback
	return apiError("ssh_set_log_callback", C.set_log_callback())
}
