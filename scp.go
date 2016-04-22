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
	"errors"
	"os"
	"unsafe"
)

// SCP - SCP protocol over SSH functions.
type Scp struct {
	scp C.ssh_scp
}

func (s Session) NewScp(mode int, location string) (Scp, error) {
	locatin_cstr := CString(location)
	defer locatin_cstr.Free()
	scp := C.ssh_scp_new(s.ptr, C.int(mode), locatin_cstr.Ptr)
	if scp != nil {
		return Scp{scp}, nil
	}
	return Scp{}, errors.New("ssh_scp_new() == nil")
}

// Initialize the scp channel.
func (s Scp) Init() error {
	return apiError("ssh_scp_init", C.ssh_scp_init(s.scp))
}

// Free a scp context.
func (s Scp) Free() {
	C.ssh_scp_free(s.scp)
}

// Close the scp channel.
func (s Scp) Close() error {
	return apiError("ssh_scp_close", C.ssh_scp_close(s.scp))
}

// Wait for a scp request (file, directory).
//
// returns:
//  SSH_SCP_REQUEST_NEWFILE: The other side is sending a file
//  SSH_SCP_REQUEST_NEWDIR: The other side is sending a directory
//  SSH_SCP_REQUEST_ENDDIR: The other side has finished with the current
//   directory SSH_SCP_REQUEST_WARNING: The other side sent us a warning
//  SSH_SCP_REQUEST_EOF: The other side finished sending us files and data.
//  SSH_ERROR: Some error happened
func (s Scp) PullRequest() int {
	return int(C.ssh_scp_pull_request(s.scp))
}

// Create a directory in a scp in sink mode
//
// dirname:
//  The name of the directory being created.
// mode:
//	The UNIX permissions for the new directory, e.g. 0755.
func (s Scp) PushDirectory(dirname string, mode int) error {
	dirname_cstr := CString(dirname)
	defer dirname_cstr.Free()
	return apiError("ssh_scp_push_directory",
		C.ssh_scp_push_directory(s.scp, dirname_cstr.Ptr, C.int(mode)))
}

// Initialize the sending of a file to a scp in sink mode.
//
// filename:
//  The name of the file being sent. It should not contain any path indicator
// size:
//  Exact size in bytes of the file being sent
// mode:
//  The UNIX permissions for the new file, e.g. 0644.
func (s Scp) PushFile(filename string, size uint, mode int) error {
	filename_cstr := CString(filename)
	defer filename_cstr.Free()
	return apiError("ssh_scp_push_file",
		C.ssh_scp_push_file(s.scp, filename_cstr.Ptr, C.size_t(size), C.int(mode)))
}

// Initialize the sending of a file to a scp in sink mode, using a 64-bit size.
func (s Scp) PushFile64(filename string, size uint64, mode int) error {
	filename_cstr := CString(filename)
	defer filename_cstr.Free()
	return apiError("ssh_scp_push_file64",
		C.ssh_scp_push_file64(s.scp, filename_cstr.Ptr, C.uint64_t(size), C.int(mode)))
}

// Read from a remote scp file.
//
// size:
//  The size to read
func (s Scp) Read(size uint) ([]byte, error) {
	buf := make([]byte, size)
	ret := C.ssh_scp_read(s.scp, unsafe.Pointer(&buf[0]), C.size_t(size))
	if ret < 0 {
		return nil, apiError("ssh_scp_read", ret)
	}
	return buf[0:ret], nil
}

// Get the name of the directory or file being pushed from the other party.
func (s Scp) GetRemoteFilename() string {
	return C.GoString(C.ssh_scp_request_get_filename(s.scp))
}

// Get the permissions of the directory or file being pushed from the other
// party.
func (s Scp) GetRemoteFilePermission() os.FileMode {
	p := C.ssh_scp_request_get_permissions(s.scp)
	return os.FileMode(p)
}

// Get the size of the file being pushed from the other party.
func (s Scp) GetRemoteFileSize() uint {
	return uint(C.ssh_scp_request_get_size(s.scp))
}

func (s Scp) GetRemoteFileSize64() uint64 {
	return uint64(C.ssh_scp_request_get_size64(s.scp))
}

// Get the warning string from a scp handle.
func (s Scp) GetWarning() string {
	w := C.ssh_scp_request_get_warning(s.scp)
	if w != nil {
		return C.GoString(w)
	}
	return ""
}

// Write into a remote scp file.
func (s Scp) Write(data []byte) error {
	return apiError("ssh_scp_write",
		C.ssh_scp_write(s.scp, unsafe.Pointer(&data[0]), C.size_t(len(data))))
}
