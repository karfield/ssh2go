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

//export sshLoggingCallback
func sshLoggingCallback(priority C.int, function, buffer *C.char, userdata unsafe.Pointer) {
	if loggingCallback != nil {
		loggingCallback.OnLogging(int(priority), C.GoString(function), C.GoString(buffer))
	}
}

/*
func SetLoggingCallback(callback LoggingCallback) error {
	loggingCallback = callback
	if C.ssh_get_log_callback() == nil {
		if C.ssh_set_log_callback(sshLoggingCallback) < 0 {
			return errors.New("Unable to set logging callback")
		}
	}
	return nil
}*/
