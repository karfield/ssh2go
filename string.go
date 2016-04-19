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
import (
	"fmt"
	"unsafe"
)

type SshString struct {
	ptr C.ssh_string
}

func NewString(bytes int) SshString {
	str := SshString{}
	str.ptr = C.ssh_string_new(C.size_t(bytes))
	return str
}

func NewStringFrom(ref string) SshString {
	cstr := CString(ref)
	defer cstr.Free()
	str := SshString{}
	str.ptr = C.ssh_string_from_char(cstr.Ptr)
	return str
}

func (s SshString) Free() {
	C.ssh_string_free(s.ptr)
}

func (s SshString) Destory() {
	C.ssh_string_burn(s.ptr)
}

func (s SshString) String() string {
	str := C.ssh_string_get_char(s.ptr)
	if str == nil {
		return ""
	}
	return C.GoString(str)
}

func (s SshString) Len() int {
	return int(C.ssh_string_len(s.ptr))
}

func (s SshString) Duplicate() SshString {
	return SshString{C.ssh_string_copy(s.ptr)}
}

func (s SshString) Copy(s2 SshString) error {
	if ret := C.ssh_string_fill(s2.ptr, C.ssh_string_data(s.ptr), C.ssh_string_len(s.ptr)); ret < 0 {
		return fmt.Errorf("ssh_string_fill() < %d", ret)
	}
	return nil
}

func (s SshString) Data() unsafe.Pointer {
	return C.ssh_string_data(s.ptr)
}
