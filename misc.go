package libssh

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>

unsigned char get_buffer_by_index(unsigned char *buf, int index) {
	return buf[index];
}
*/
import "C"
import (
	"fmt"
	"strconv"
	"unsafe"
)

type CStringWrapper struct {
	Ptr *C.char
}

func CString(str string) CStringWrapper {
	return CStringWrapper{C.CString(str)}
}

func (cstr CStringWrapper) Free() {
	C.free(unsafe.Pointer(cstr.Ptr))
}

func CBool(val bool) C.int {
	var ret C.int = 0
	if val {
		ret = 1
	}
	return ret
}

type Counter struct {
	InBytes    uint64
	OutBytes   uint64
	InPackets  uint64
	OutPackets uint64
}

func (c Counter) toCCounter() C.ssh_counter {
	return &C.struct_ssh_counter_struct{
		in_bytes:    C.uint64_t(c.InBytes),
		out_bytes:   C.uint64_t(c.OutBytes),
		in_packets:  C.uint64_t(c.InPackets),
		out_packets: C.uint64_t(c.OutPackets),
	}
}

func copyData(data interface{}, len interface{}) []byte {
	var (
		ptr    *C.uchar
		length int = 0
	)
	if p, ok := data.(*C.uchar); ok {
		ptr = p
	} else if p2, ok := data.(*C.char); ok {
		ptr = (*C.uchar)(unsafe.Pointer(p2))
	} else if p3, ok := data.(unsafe.Pointer); ok {
		ptr = (*C.uchar)(p3)
	} else {
		return []byte{}
	}
	if l, ok := len.(C.uint32_t); ok {
		length = int(l)
	} else if l2, ok := len.(C.size_t); ok {
		length = int(l2)
	} else if l3, ok := len.(C.int); ok {
		length = int(l3)
	}
	if length == 0 {
		return []byte{}
	}
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = byte(C.get_buffer_by_index(ptr, C.int(i)))
	}
	return buf
}

type SshApiError struct {
	fn  string
	err string
}

func (e *SshApiError) Error() string {
	return fmt.Sprintf("libssh call %s() returns %s", e.fn, e.err)
}

func apiError(fn string, err interface{}) error {
	errno := 0
	if e, ok := err.(C.int); ok {
		errno = int(e)
	} else if e1, ok := err.(C.size_t); ok {
		errno = int(e1)
	} else if e3, ok := err.(int); ok {
		errno = e3
	} else if estr, ok := err.(string); ok {
		return &SshApiError{fn, estr}
	} else if e4, ok := err.(C.socket_t); ok {
		errno = int(e4)
	} else {
		return nil
	}
	if errno < 0 {
		return &SshApiError{fn, strconv.Itoa(errno)}
	}
	return nil
}

func apiErrorWithNullString(fn string, result *C.char) (string, error) {
	if result == nil {
		return "", apiError(fn, "NULL")
	}
	return C.GoString(result), nil
}
