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
import "unsafe"

type Channel struct {
	ptr     C.ssh_channel
	Session *Session
	Port    int
}

func (s *Session) NewChannel() *Channel {
	ch := C.ssh_channel_new(s.ptr)
	if ch == nil {
		return nil
	}
	return &Channel{ch, s, 0}
}

// Accept an incoming TCP/IP forwarding channel and get information about
// incomming connection.
func (s *Session) AcceptForward(timeoutMs int, port int) *Channel {
	var port_ptr *C.int = nil
	if port > 0 {
		port_c := C.int(port)
		port_ptr = &port_c
	}
	ch := C.ssh_channel_accept_forward(s.ptr, C.int(timeoutMs), port_ptr)
	if ch == nil {
		return nil
	}
	if port_ptr != nil {
		return &Channel{ch, s, int(*port_ptr)}
	}
	return &Channel{ch, s, 0}
}

// Accept an X11 forwarding channel.
func (c *Channel) AcceptX11(timeoutMs int) *Channel {
	ch := C.ssh_channel_accept_x11(c.ptr, C.int(timeoutMs))
	if ch == nil {
		return nil
	}
	return &Channel{ch, c.Session, 0}
}

// Sends the "cancel-tcpip-forward" global request to ask the server to cancel
// the tcpip-forward request.
func (s *Session) CancelForward(address string, port int) error {
	address_cstr := CString(address)
	defer address_cstr.Free()
	return commonError(C.ssh_channel_cancel_forward(s.ptr, address_cstr.Ptr, C.int(port)))
}

// Sends the "tcpip-forward" global request to ask the server to begin listening
// for inbound connections.
//
// address:
//  The address to bind to on the server. Pass NULL to bind to all available
//  addresses on all protocol families supported by the server.
// port:
//  The port to bind to on the server. Pass 0 to ask the server to allocate the
//  next available unprivileged port number
//
// return:
//  actual bound port.
func (s *Session) ListenForward(address string, port int) (int, error) {
	address_cstr := CString(address)
	defer address_cstr.Free()
	var port_c C.int = 0
	err := commonError(C.ssh_channel_listen_forward(s.ptr, address_cstr.Ptr, C.int(port), &port_c))
	return int(port_c), err
}

// Change the size of the terminal associated to a channel.
//
// cols:
//  The new number of columns
// rows:
//  The new number of rows.
//
// Do not call it from a signal handler if you are not sure any other libssh
// function using the same channel/session is running at same time (not 100%
// threadsafe).
func (c *Channel) ChangePtySize(cols, row int) error {
	return commonError(C.ssh_channel_change_pty_size(c.ptr, C.int(cols), C.int(row)))
}

// Close a channel.
//
// This sends an end of file and then closes the channel. You won't be able to
// recover any data the server was going to send or was in buffers.
func (c *Channel) Close() error {
	return commonError(C.ssh_channel_close(c.ptr))
}

// Close and free a channel
func (c *Channel) Free() {
	C.ssh_channel_free(c.ptr)
}

// Get the exit status of the channel (error code from the executed
// instruction).
//
// return:
// The exit status, -1 if no exit status has been returned (yet).
//
// Warning!!!
// This function may block until a timeout (or never) if the other side is not
// willing to close the channel.
//
// If you're looking for an async handling of this register a callback for the
// exit status.
func (c *Channel) GetExitStatus() int {
	return int(C.ssh_channel_get_exit_status(c.ptr))
}

// Recover the session in which belongs a channel.
func (c *Channel) GetSession() *Session {
	return c.Session
}

// Check if the channel is closed or not.
func (c *Channel) IsClosed() bool {
	return C.ssh_channel_is_closed(c.ptr) != 0
}

// Check if remote has sent an EOF
func (c *Channel) IsEof() bool {
	return C.ssh_channel_is_eof(c.ptr) != 0
}

// Check if the channel is open or not
func (c *Channel) IsOpen() bool {
	return C.ssh_channel_is_open(c.ptr) != 0
}

// Open an agent authentication forwarding channel.
//
// This type of channel can be opened by a server towards a client in order to
// provide SSH-Agent services to the server-side process. This channel can only
// be opened if the client claimed support by sending a channel request
// beforehand.
func (c *Channel) OpenAuthAgent() error {
	return commonError(C.ssh_channel_open_auth_agent(c.ptr))
}

// Open a TCP/IP forwarding channel.
//
// remotehost:
//  The remote host to connected (host name or IP).
// remoteport:
//  The remote port.
// sourcehost:
//  The numeric IP address of the machine from where the connection request
//  originates. This is mostly for logging purposes.
// localport:
//  The port on the host from where the connection originated. This is mostly
//  for logging purposes.
//
// Warning:
//  This function does not bind the local port and does not automatically
//  forward the content of a socket to the channel. You still have to use
//  channel_read and channel_write for this.
func (c *Channel) OpenForward(remoteHost string, remotePort int, sourceHost string, localPort int) error {
	remoteHost_s := CString(remoteHost)
	defer remoteHost_s.Free()
	sourceHost_s := CString(sourceHost)
	defer sourceHost_s.Free()
	return commonError(C.ssh_channel_open_forward(c.ptr, remoteHost_s.Ptr, C.int(remotePort), sourceHost_s.Ptr, C.int(localPort)))
}

// Open a TCP/IP reverse forwarding channel.
//
// Warning
//  This function does not bind the local port and does not automatically
//  forward the content of a socket to the channel. You still have to use
//  channel_read and channel_write for this.
/*func (c *Channel) OpenReverseForward(remoteHost string, remotePort int, sourceHost string, localPort int) error {
	remoteHost_s := CString(remoteHost)
	defer remoteHost_s.Free()
	sourceHost_s := CString(sourceHost)
	defer sourceHost_s.Free()
	return commonError(C.ssh_channel_open_reverse_forward(c.ptr, remoteHost_s.Ptr, C.int(remotePort), sourceHost_s.Ptr, C.int(localPort)))
}*/

// Open a session channel (suited for a shell, not TCP forwarding).
func (c *Channel) OpenSession() error {
	return commonError(C.ssh_channel_open_session(c.ptr))
}

// Open a X11 channel.
//
// Warning:
//  This function does not bind the local port and does not automatically
//  forward the content of a socket to the channel. You still have to use
//  channel_read and channel_write for this.
func (c *Channel) OpenX11(originAddr string, originPort int) error {
	originAddr_cstr := CString(originAddr)
	defer originAddr_cstr.Free()
	return commonError(C.ssh_channel_open_x11(c.ptr, originAddr_cstr.Ptr, C.int(originPort)))
}

// Polls a channel for data to read.
//
// isStderr:
//  A boolean to select the stderr stream.
//
// Returns
//  The number of bytes available for reading, 0 if nothing is available or
//  SSH_ERROR on error.
//
// Warning
//  When the channel is in EOF state, the function returns SSH_EOF.
func (c *Channel) Poll(isStderr bool) (int, error) {
	ret := C.ssh_channel_poll(c.ptr, CBool(isStderr))
	if err := commonError(ret); err != nil {
		return 0, err
	}
	return int(ret), nil
}

// Polls a channel for data to read, waiting for a certain timeout.
//
// timeout:
//		Set an upper limit on the time for which this function will block, in
//		milliseconds. Specifying a negative value means an infinite timeout.
//		This parameter is passed to the poll( function.)
// isStderr:
//  A boolean to select the stderr stream.
func (c *Channel) PollTimeout(timeout int, isStderr bool) (int, error) {
	ret := C.ssh_channel_poll_timeout(c.ptr, C.int(timeout), CBool(isStderr))
	if err := commonError(ret); err != nil {
		return 0, err
	}
	return int(ret), nil
}

// Reads data from a channel.
//
// count:
//  The count of bytes to be read.
// Warning
// This function may return less than count bytes of data, and won't block until
// count bytes have been read.
// The read function using a buffer has been renamed to channel_read_buffer()
func (c *Channel) Read(count int, isStderr bool) ([]byte, error) {
	buf := make([]byte, count)
	ret := C.ssh_channel_read(c.ptr, unsafe.Pointer(&buf[0]), C.uint32_t(count), CBool(isStderr))
	if ret > 0 {
		return buf, nil
	}
	return nil, commonError(ret)
}

// Do a nonblocking read on the channel
// A nonblocking read on the specified channel. it will return <= count bytes of
// data read atomically.
func (c *Channel) ReadNonblocking(count int, isStderr bool) ([]byte, error) {
	buf := make([]byte, count)
	ret := C.ssh_channel_read_nonblocking(c.ptr, unsafe.Pointer(&buf[0]), C.uint32_t(count), CBool(isStderr))
	if ret > 0 {
		return buf, nil
	}
	return nil, commonError(ret)
}

func (c *Channel) ReadTimeout(timeout, count int, isStderr bool) ([]byte, error) {
	buf := make([]byte, count)
	ret := C.ssh_channel_read_timeout(c.ptr, unsafe.Pointer(&buf[0]), C.uint32_t(count), CBool(isStderr), C.int(timeout))
	if ret > 0 {
		return buf, nil
	}
	return nil, commonError(ret)
}

// Send an "auth-agent-req" channel request over an existing session channel.
//
// This client-side request will enable forwarding the agent over an secure
// tunnel. When the server is ready to open one authentication agent channel, an
// ssh_channel_open_request_auth_agent_callback event will be generated.
func (c *Channel) SendAuthAgentRequest() error {
	return commonError(C.ssh_channel_request_auth_agent(c.ptr))
}

// Set environment variables
//
// name
//	The name of the variable.
// value
//  The value to set.
//
// Warning
//  Some environment variables may be refused by security reasons.
func (c *Channel) SendEnvRequest(name, value string) error {
	name_cstr := CString(name)
	defer name_cstr.Free()
	value_cstr := CString(value)
	defer value_cstr.Free()
	return commonError(C.ssh_channel_request_env(c.ptr, name_cstr.Ptr, value_cstr.Ptr))
}

// Run a shell command without an interactive shell.
//
// cmdline:
//  The command to execute (e.g. "ls ~/ -al | grep -i reports").
//
// This is similar to 'sh -c command'.
func (c *Channel) Exec(cmdline string) error {
	cmdline_cstr := CString(cmdline)
	defer cmdline_cstr.Free()
	return commonError(C.ssh_channel_request_exec(c.ptr, cmdline_cstr.Ptr))
}

// Request a PTY.
func (c *Channel) SendPtyRequest() error {
	return commonError(C.ssh_channel_request_pty(c.ptr))
}

// Request a pty with a specific type and size
//
// terminal
//  The terminal type ("vt100, xterm,...")
func (c *Channel) SendPtySize(termType string, cols, rows int) error {
	termType_cstr := CString(termType)
	defer termType_cstr.Free()
	return commonError(C.ssh_channel_request_pty_size(c.ptr, termType_cstr.Ptr, C.int(cols), C.int(rows)))
}

// Send an exit signal to remote process (RFC 4254, section 6.10).
//
// This sends the exit status of the remote process. Note, that remote system
// may not support signals concept. In such a case this request will be silently
// ignored. Only SSH-v2 is supported (I'm not sure about SSH-v1).
//
// sig:
//  The signal to send (without SIG prefix) (e.g. "TERM" or "KILL").
// coreDump:
//  A boolean to tell if a core was dumped
// errmsg:
//  A CRLF explanation text about the error condition
// lang:
//  The language used in the message (format: RFC 3066)
/*func (c *Channel) SendExitSignal(sig string, coreDump bool, errmsg, lang string) error {
	sig_cstr := CString(sig)
	defer sig_cstr.Free()
	errmsg_cstr := CString(errmsg)
	defer errmsg_cstr.Free()
	lang_cstr := CString(lang)
	defer lang_cstr.Free()
	return commonError(C.ssh_channel_request_send_exit_signal(c.ptr, sig_cstr, CBool(coreDump), errmsg_cstr, lang_cstr))
}*/

// Send the exit status to the remote process
//
// Sends the exit status to the remote process (as described in RFC 4254,
// section 6.10). Only SSH-v2 is supported (I'm not sure about SSH-v1).
/*func (c *Channel) SendExitStatus(status int) error {
	return commonError(C.ssh_channel_request_send_exit_status(c.ptr, C.int(status)))
}*/

// Send a signal to remote process (as described in RFC 4254, section 6.9).
//
// Sends a signal 'sig' to the remote process. Note, that remote system may not
// support signals concept. In such a case this request will be silently
// ignored. Only SSH-v2 is supported (I'm not sure about SSH-v1).
//
// OpenSSH doesn't support signals yet, see:
// https://bugzilla.mindrot.org/show_bug.cgi?id=1424
//
// sig:
//		The signal to send (without SIG prefix)
//
//      SIGABRT -> ABRT
//      SIGALRM -> ALRM
//      SIGFPE -> FPE
//      SIGHUP -> HUP
//      SIGILL -> ILL
//      SIGINT -> INT
//      SIGKILL -> KILL
//      SIGPIPE -> PIPE
//      SIGQUIT -> QUIT
//      SIGSEGV -> SEGV
//      SIGTERM -> TERM
//      SIGUSR1 -> USR1
//      SIGUSR2 -> USR2
func (c *Channel) SendSignal(sig string) error {
	sig_cstr := CString(sig)
	defer sig_cstr.Free()
	return commonError(C.ssh_channel_request_send_signal(c.ptr, sig_cstr.Ptr))
}

// Request a shell.
func (c *Channel) SendShellRequest() error {
	return commonError(C.ssh_channel_request_shell(c.ptr))
}

// Request a subsystem (for example "sftp").
//
func (c *Channel) SendSubsystemRequest(subsys string) error {
	subsys_cstr := CString(subsys)
	defer subsys_cstr.Free()
	return commonError(C.ssh_channel_request_subsystem(c.ptr, subsys_cstr.Ptr))
}

// Sends the "x11-req" channel request over an existing session channel.
//
// This will enable redirecting the display of the remote X11 applications to
// local X server over an secure tunnel.
//
// singleConnection:
//  A boolean to mark only one X11 app will be redirected.
// protocol:
//  A x11 authentication protocol. Pass NULL to use the default value
//  MIT-MAGIC-COOKIE-1.
// cookie:
//  A x11 authentication cookie. Pass NULL to generate a random cookie.
// screenNumber:
//  The screen number.
func (c *Channel) SendX11Request(singleConnection bool, protocol, cookie string, screenNumber int) error {
	protocol_cstr := CString(protocol)
	defer protocol_cstr.Free()
	cookie_cstr := CString(cookie)
	defer cookie_cstr.Free()
	return commonError(C.ssh_channel_request_x11(c.ptr, CBool(singleConnection), protocol_cstr.Ptr, cookie_cstr.Ptr, C.int(screenNumber)))
}

// Send an end of file on the channel.
//
// This doesn't close the channel. You may still read from it but not write.
func (c *Channel) SendEOF() error {
	return commonError(C.ssh_channel_send_eof(c.ptr))
}

// Put the channel into blocking or nonblocking mode.
//
// Warning
//  A side-effect of this is to put the whole session in non-blocking mode.
func (c *Channel) SetBlocking(blocking bool) {
	C.ssh_channel_set_blocking(c.ptr, CBool(blocking))
}

// Set the channel data counter.
func (c *Channel) SetCounter(counter Counter) {
	C.ssh_channel_set_counter(c.ptr, counter.toCCounter())
}

// Blocking write on a channel.
func (c *Channel) Write(data []byte) error {
	len := len(data)
	if len == 0 {
		return nil
	}
	data_ptr := unsafe.Pointer(&data[0])
	return commonError(C.ssh_channel_write(c.ptr, data_ptr, C.uint32_t(len)))
}

// Blocking write on a channel stderr.
/*func (c *Channel) WriteStderr(data []byte) error {
	len = len(data)
	if len == 0 {
		return nil
	}
	data_ptr := unsafe.Pointer(&data[0])
	return commonError(C.ssh_channel_write_stderr(c.ptr, data_ptr, len))
}*/
