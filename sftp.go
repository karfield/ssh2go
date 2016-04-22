package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <libssh/libssh.h>
#define WITH_SERVER 1
#include <libssh/sftp.h>
*/
import "C"
import (
	"syscall"
	"time"
	"unsafe"
)

type SftpSession struct {
	ptr C.sftp_session
}

type SftpFile struct {
	ptr C.sftp_file
}

type SftpAttributes struct {
	ptr C.sftp_attributes
}

type SftpDir struct {
	ptr C.sftp_dir
}

func (s Session) NewSftp() SftpSession {
	sftp := SftpSession{}
	sftp.ptr = C.sftp_new(s.ptr)
	return sftp
}

func (c Channel) NewSftp() SftpSession {
	sftp := SftpSession{}
	s := c.GetSession()
	sftp.ptr = C.sftp_new_channel(s.ptr, c.ptr)
	return sftp
}

func (f SftpSession) Free() {
	C.sftp_free(f.ptr)
}

func (s SftpSession) getError(fn string, err C.int) error {
	if err < 0 {
		return apiError(fn, C.sftp_get_error(s.ptr))
	}
	return nil
}

func (s SftpSession) Init() error {
	return s.getError("sftp_init", C.sftp_init(s.ptr))
}

// Get extensions provided by the server.
func (s SftpSession) GetExtensionNames() []string {
	exts := []string{}
	cnt := C.sftp_extensions_get_count(s.ptr)
	for i := 0; i < int(cnt); i++ {
		ext := C.sftp_extensions_get_name(s.ptr, C.uint(i))
		exts = append(exts, C.GoString(ext))
	}
	return exts
}

func (s SftpSession) GetExtensionData(index int) string {
	return C.GoString(C.sftp_extensions_get_data(s.ptr, C.uint(index)))
}

func (s SftpSession) IsExtensionSupported(name, data string) bool {
	name_cstr := CString(name)
	defer name_cstr.Free()
	data_cstr := CString(data)
	defer data_cstr.Free()
	return C.sftp_extension_supported(s.ptr, name_cstr.Ptr, data_cstr.Ptr) == 1
}

func (s SftpSession) OpenDir(path string) (SftpDir, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	dir := SftpDir{}
	dir.ptr = C.sftp_opendir(s.ptr, path_cstr.Ptr)
	if dir.ptr == nil {
		return dir, apiError("sftp_opendir", "NULL")
	}
	return dir, nil
}

func (s SftpSession) ReadDir(dir SftpDir) (SftpAttributes, error) {
	attrs := C.sftp_readdir(s.ptr, dir.ptr)
	if attrs == nil {
		return SftpAttributes{}, apiError("sftp_readdir", "NULL")
	}
	return SftpAttributes{attrs}, nil
}

func (s SftpDir) EOF() bool {
	return C.sftp_dir_eof(s.ptr) == 1
}

func (s SftpSession) Stat(path string) (SftpAttributes, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	attrs := C.sftp_stat(s.ptr, path_cstr.Ptr)
	if attrs == nil {
		return SftpAttributes{}, s.getError("sftp_stat", -1)
	}
	return SftpAttributes{attrs}, nil
}

func (s SftpSession) Lstat(path string) (SftpAttributes, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	attrs := C.sftp_lstat(s.ptr, path_cstr.Ptr)
	if attrs == nil {
		return SftpAttributes{}, s.getError("sftp_lstat", -1)
	}
	return SftpAttributes{attrs}, nil
}

func (s SftpFile) Fstat() (SftpAttributes, error) {
	attrs := C.sftp_fstat(s.ptr)
	if attrs == nil {
		w := SftpSession{s.ptr.sftp}
		return SftpAttributes{}, w.getError("sftp_fstat", -1)
	}
	return SftpAttributes{attrs}, nil
}

func (s SftpAttributes) Free() {
	C.sftp_attributes_free(s.ptr)
}

func (s SftpDir) Close() error {
	return apiError("sftp_closedir", C.sftp_closedir(s.ptr))
}

func (s SftpFile) Close() error {
	return apiError("sftp_close", C.sftp_close(s.ptr))
}

func (s SftpSession) Open(path string, accessType int, mode int) (SftpFile, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	file := C.sftp_open(s.ptr, path_cstr.Ptr, C.int(accessType), C.mode_t(mode))
	if file == nil {
		return SftpFile{}, s.getError("sftp_open", -1)
	}
	return SftpFile{file}, nil
}

func (s SftpFile) SetNonBlocking() {
	C.sftp_file_set_nonblocking(s.ptr)
}

func (s SftpFile) SetBlocking() {
	C.sftp_file_set_blocking(s.ptr)
}

func (s SftpFile) Read(length int) ([]byte, error) {
	buf := make([]byte, length)
	ret := C.sftp_read(s.ptr, unsafe.Pointer(&buf[0]), C.size_t(length))
	if ret < 0 {
		session := SftpSession{s.ptr.sftp}
		return nil, session.getError("sftp_read", -1)
	}
	return buf[0:ret], nil
}

// Start an asynchronous read from a file using an opened sftp file handle.
//
// Its goal is to avoid the slowdowns related to the request/response pattern of
// a synchronous read. To do so, you must call 2 functions:
// sftp_async_read_begin() and sftp_async_read()
//
// The first step is to call sftp_async_read_begin(). This function returns a
// request identifier. The second step is to call sftp_async_read() using the
// returned identifier.
//
// Returns:
// An identifier corresponding to the sent request
//
// Warning:
// When calling this function, the internal offset is updated corresponding to
// the len parameter.
// A call to sftp_async_read_begin() sends a request to the server. When the
// server answers, libssh allocates memory to store it until sftp_async_read() is
// called. Not calling sftp_async_read() will lead to memory leaks.
//
func (f SftpFile) AsyncReadBegin(readSize int) (int, error) {
	id := int(C.sftp_async_read_begin(f.ptr, C.uint32_t(readSize)))
	if id < 0 {
		return 0, apiError("sftp_async_read_begin", id)
	}
	return id, nil
}

// Wait for an asynchronous read to complete and save the data.
func (f SftpFile) AsyncRead(id, readSize int) ([]byte, error) {
	buf := make([]byte, readSize)
	ret := C.sftp_async_read(f.ptr, unsafe.Pointer(&buf[0]), C.uint32_t(readSize), C.uint32_t(id))
	if ret < 0 {
		return nil, apiError("sftp_async_read", ret)
	}
	return buf[0:ret], nil
}

// Write to a file using an opened sftp file handle.
func (f SftpFile) Write(data []byte) (int, error) {
	count := C.sftp_write(f.ptr, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	if count < 0 {
		return 0, apiError("sftp_write", count)
	}
	return int(count), nil
}

// Seek to a specific location in a file.
func (f SftpFile) Seek(newOffset uint) error {
	if r := C.sftp_seek(f.ptr, C.uint32_t(newOffset)); r < 0 {
		return apiError("sftp_seek", r)
	}
	return nil
}

func (f SftpFile) Seek64(newOffset uint64) error {
	if r := C.sftp_seek64(f.ptr, C.uint64_t(newOffset)); r < 0 {
		return apiError("sftp_seek64", r)
	}
	return nil
}

func (f SftpFile) Tell() uint32 {
	return uint32(C.sftp_tell(f.ptr))
}

func (f SftpFile) Tell64() uint64 {
	return uint64(C.sftp_tell64(f.ptr))
}

func (f SftpFile) Rewind() {
	C.sftp_rewind(f.ptr)
}

func (s SftpSession) Unlink(path string) error {
	path_cstr := CString(path)
	defer path_cstr.Free()
	return s.getError("sftp_unlink", C.sftp_unlink(s.ptr, path_cstr.Ptr))
}

func (s SftpSession) Rmdir(path string) error {
	path_cstr := CString(path)
	defer path_cstr.Free()
	return s.getError("sftp_rmdir", C.sftp_rmdir(s.ptr, path_cstr.Ptr))
}

func (s SftpSession) Mkdir(path string, mode int) error {
	path_cstr := CString(path)
	defer path_cstr.Free()
	return s.getError("sftp_mkdir", C.sftp_mkdir(s.ptr, path_cstr.Ptr, C.mode_t(mode)))
}

func (s SftpSession) Rename(oldpath, newpath string) error {
	oldpath_cstr := CString(oldpath)
	defer oldpath_cstr.Free()
	newpath_cstr := CString(newpath)
	defer newpath_cstr.Free()
	return s.getError("sftp_rename", C.sftp_rename(s.ptr, oldpath_cstr.Ptr, newpath_cstr.Ptr))
}

func (s SftpSession) SetStat(file string, attrs SftpAttributes) error {
	file_cstr := CString(file)
	defer file_cstr.Free()
	return s.getError("sftp_setstat", C.sftp_setstat(s.ptr, file_cstr.Ptr, attrs.ptr))
}

func (s SftpSession) Chown(file string, owner, group int) error {
	file_cstr := CString(file)
	defer file_cstr.Free()
	return s.getError("sftp_chown", C.sftp_chown(s.ptr, file_cstr.Ptr, C.uid_t(owner), C.gid_t(group)))
}

func (s SftpSession) Chmod(file string, mode int) error {
	file_cstr := CString(file)
	defer file_cstr.Free()
	return s.getError("sftp_chmod", C.sftp_chmod(s.ptr, file_cstr.Ptr, C.mode_t(mode)))
}

func (s SftpSession) Utimes(file string, mtime time.Time) error {
	tv := syscall.NsecToTimeval(mtime.UnixNano())
	file_cstr := CString(file)
	defer file_cstr.Free()
	return s.getError("sftp_utimes", C.sftp_utimes(s.ptr, file_cstr.Ptr, (*C.struct_timeval)(unsafe.Pointer(&tv))))
}

func (s SftpSession) Symlink(from, to string) error {
	from_cstr := CString(from)
	defer from_cstr.Free()
	to_cstr := CString(to)
	defer to_cstr.Free()
	return s.getError("sftp_symlink", C.sftp_symlink(s.ptr, from_cstr.Ptr, to_cstr.Ptr))
}

func (s SftpSession) Readlink(link string) (string, error) {
	link_cstr := CString(link)
	defer link_cstr.Free()
	dest := C.sftp_readlink(s.ptr, link_cstr.Ptr)
	if dest == nil {
		return "", s.getError("sftp_readlink", -1)
	}
	return C.GoString(dest), nil
}

type SftpFsInfo struct {
	ptr C.sftp_statvfs_t
}

func (s SftpSession) FsInfo(path string) (SftpFsInfo, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	stat := C.sftp_statvfs(s.ptr, path_cstr.Ptr)
	if stat == nil {
		return SftpFsInfo{}, s.getError("sftp_statvfs", -1)
	}
	return SftpFsInfo{stat}, nil
}

func (s SftpFile) FsInfo() (SftpFsInfo, error) {
	info := C.sftp_fstatvfs(s.ptr)
	if info == nil {
		s := SftpSession{s.ptr.sftp}
		return SftpFsInfo{}, s.getError("sftp_statvfs", -1)
	}
	return SftpFsInfo{info}, nil
}

func (s SftpFsInfo) Free() {
	C.sftp_statvfs_free(s.ptr)
}

func (s SftpSession) CanonicalizePath(path string) (string, error) {
	path_cstr := CString(path)
	defer path_cstr.Free()
	p := C.sftp_canonicalize_path(s.ptr, path_cstr.Ptr)
	if p == nil {
		return "", apiError("sftp_canonicalize_path", "NULL")
	}
	return C.GoString(p), nil
}

func (s SftpSession) ServerVersion() int {
	return int(C.sftp_server_version(s.ptr))
}

func (c Channel) NewSftpServer() (SftpSession, error) {
	s := c.GetSession()
	sftp := C.sftp_server_new(s.ptr, c.ptr)
	if sftp == nil {
		return SftpSession{}, apiError("sftp_server_new", -1)
	}
	return SftpSession{sftp}, nil
}

func (s SftpSession) InitServer() error {
	return apiError("sftp_server_init", C.sftp_server_init(s.ptr))
}

type SftpPacket struct {
	packet C.sftp_packet
}

func (s SftpSession) ReadPacket() (SftpPacket, error) {
	p := SftpPacket{}
	p.packet = C.sftp_packet_read(s.ptr)
	if p.packet == nil {
		return p, apiError("sftp_packet_read", "NULL")
	}
	return p, nil
}

func (p SftpPacket) Free() {
	C.sftp_packet_free(p.packet)
}

func (s SftpSession) WritePacket(typ int, payload Buffer) error {
	return apiError("sftp_packet_write", C.sftp_packet_write(s.ptr, C.uint8_t(typ), payload.ptr))
}

func (b Buffer) AddAttributes(attr SftpAttributes) error {
	return apiError("buffer_add_attributes", C.buffer_add_attributes(b.ptr, attr.ptr))
}

func (s SftpSession) ParseBuffer(buffer Buffer, expectName int) (SftpAttributes, error) {
	attr := C.sftp_parse_attr(s.ptr, buffer.ptr, C.int(expectName))
	if attr == nil {
		return SftpAttributes{}, apiError("sftp_parse_attr", "NULL")
	}
	return SftpAttributes{attr}, nil
}

type SftpClientMessage struct {
	msg C.sftp_client_message
}

func (s SftpSession) GetClientMessage() (SftpClientMessage, error) {
	m := C.sftp_get_client_message(s.ptr)
	if m == nil {
		return SftpClientMessage{}, apiError("sftp_get_client_message", "NULL")
	}
	return SftpClientMessage{m}, nil
}

func (m SftpClientMessage) Free() {
	C.sftp_client_message_free(m.msg)
}

func (m SftpClientMessage) GetType() int {
	return int(C.sftp_client_message_get_type(m.msg))
}

func (m SftpClientMessage) GetFilename() string {
	return C.GoString(C.sftp_client_message_get_filename(m.msg))
}

func (m SftpClientMessage) SetFilename(name string) {
	name_cstr := CString(name)
	defer name_cstr.Free()
	C.sftp_client_message_set_filename(m.msg, name_cstr.Ptr)
}

func (m SftpClientMessage) GetData() string {
	return C.GoString(C.sftp_client_message_get_data(m.msg))
}

func (m SftpClientMessage) GetFlags() uint {
	return uint(C.sftp_client_message_get_flags(m.msg))
}

func (s SftpSession) SendMessage(m SftpClientMessage) error {
	return apiError("sftp_send_client_message", C.sftp_send_client_message(s.ptr, m.msg))
}

func (m SftpClientMessage) ReplyName(name string, attr SftpAttributes) error {
	name_cstr := CString(name)
	defer name_cstr.Free()
	return apiError("sftp_reply_name", C.sftp_reply_name(m.msg, name_cstr.Ptr, attr.ptr))
}

func (m SftpClientMessage) ReplyAttr(attr SftpAttributes) error {
	return apiError("sftp_reply_attr", C.sftp_reply_attr(m.msg, attr.ptr))
}

func (m SftpClientMessage) ReplyStatus(status uint, message string) error {
	msg := CString(message)
	defer msg.Free()
	return apiError("sftp_reply_status", C.sftp_reply_status(m.msg, C.uint32_t(status), msg.Ptr))
}

func (m SftpClientMessage) ReplyNamesAdd(file, longname string, attr SftpAttributes) error {
	file_cstr := CString(file)
	defer file_cstr.Free()
	longname_cstr := CString(longname)
	defer longname_cstr.Free()
	return apiError("sftp_reply_names_add", C.sftp_reply_names_add(m.msg, file_cstr.Ptr, longname_cstr.Ptr, attr.ptr))
}

func (m SftpClientMessage) ReplyNameCount() int {
	return int(C.sftp_reply_names(m.msg))
}

func (m SftpClientMessage) ReplyData(maxlen int) ([]byte, error) {
	buf := make([]byte, maxlen)
	r := C.sftp_reply_data(m.msg, unsafe.Pointer(&buf[0]), C.int(maxlen))
	if r < 0 {
		return nil, apiError("sftp_reply_data", r)
	}
	return buf[0:r], nil
}

func (m SftpClientMessage) ReplyHandle(handle SshString) error {
	return apiError("sftp_reply_handle", C.sftp_reply_handle(m.msg, handle.ptr))
}

func (s SftpSession) AllocHandle(handle unsafe.Pointer) (SshString, error) {
	m := C.sftp_handle_alloc(s.ptr, handle)
	if m == nil {
		return SshString{}, apiError("sftp_handle_alloc", "NULL")
	}
	return SshString{m}, nil
}

func (s SftpSession) Handle(h SshString) unsafe.Pointer {
	return C.sftp_handle(s.ptr, h.ptr)
}

func (s SftpSession) RemoveHandle(handle unsafe.Pointer) {
	C.sftp_handle_remove(s.ptr, handle)
}
