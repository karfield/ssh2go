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

import (
	"errors"
	"unsafe"
)

type Session struct {
	ptr C.ssh_session
}

func NewSession() (*Session, error) {
	session := &Session{}
	session.ptr = C.ssh_new()
	if session.ptr == nil {
		return nil, errors.New("Unable to allocate ssh session")
	}
	return session, nil
}

// Blocking flush of the outgoing buffer.
//
// timeout:
// Set an upper limit on the time for which this function will block, in
// milliseconds. Specifying -1 means an infinite timeout. This parameter is
// passed to the poll( function.)
func (s *Session) BlockingFlush(timeout int) error {
	return commonError(C.ssh_blocking_flush(s.ptr, C.int(timeout)))
}

// Connect to the ssh server
//
func (s *Session) Connect() error {
	return commonError(C.ssh_connect(s.ptr))
}

// Disconnect from a session (client or server).
//
// The session can then be reused to open a new session.
func (s *Session) Disconnect() {
	C.ssh_disconnect(s.ptr)
}

// Deallocate a SSH session handle.
func (s *Session) Free() {
	C.ssh_free(s.ptr)
}

// get the name of the input cipher for the given session.
func (s *Session) GetCipherIn() string {
	ciphername := C.ssh_get_cipher_in(s.ptr)
	if ciphername == nil {
		return ""
	}
	return C.GoString(ciphername)
}

// get the name of the output cipher for the given session
func (s *Session) GetCipherOut() string {
	ciphername := C.ssh_get_cipher_out(s.ptr)
	if ciphername == nil {
		return ""
	}
	return C.GoString(ciphername)
}

// get the client banner
func (s *Session) GetClientBanner() string {
	banner := C.ssh_get_clientbanner(s.ptr)
	if banner == nil {
		return ""
	}
	return C.GoString(banner)
}

// Get the disconnect message from the server.
//
func (s *Session) GetDisconnectMessage() string {
	message := C.ssh_get_disconnect_message(s.ptr)
	if message == nil {
		return ""
	}
	return C.GoString(message)
}

// Get the fd of a connection
//
// In case you'd need the file descriptor of the connection to the
// server/client.
func (s *Session) GetFd() int {
	socketFd := C.ssh_get_fd(s.ptr)
	return int(socketFd)
}

// get the name of the input HMAC algorithm for the given session.
//
// Returns HMAC algorithm name or "" if unknown.
func (s *Session) GetHMacIn() string {
	name := C.ssh_get_hmac_in(s.ptr)
	if name == nil {
		return ""
	}
	return C.GoString(name)
}

// get the name of the output HMAC algorithm for the given session.
//
// Returns HMAC algorithm name or "" if unknown.
func (s *Session) GetHMacOut() string {
	name := C.ssh_get_hmac_out(s.ptr)
	if name == nil {
		return ""
	}
	return C.GoString(name)
}

// GetIssueBanner()
//
// Get the issue banner from the server.
//
// This is the banner showing a disclaimer to users who log in, typically their right or the fact that they will be monitored.
//
// Return A newly allocated string with the banner, "" on error.
func (s *Session) GetIssueBanner() string {
	banner := C.ssh_get_issue_banner(s.ptr)
	if banner == nil {
		return ""
	}
	return C.GoString(banner)
}

// GetKeyExchangeAlgorithm()
//
// get the name of the current key exchange algorithm.
func (s *Session) GetKeyExchangeAlgorithm() string {
	algorithm := C.ssh_get_kex_algo(s.ptr)
	return C.GoString(algorithm)
}

// Get the version of the OpenSSH server, if it is not an OpenSSH server then 0
// will be returned.
func (s *Session) GetOpensshVersion() int {
	return int(C.ssh_get_openssh_version(s.ptr))
}

// GetPollFlags()
//
// Get poll flags for an external mainloop.
// Return A bitmask including SSH_READ_PENDING or SSH_WRITE_PENDING.
// For SSH_READ_PENDING, your invocation of poll( should include POLLIN.
// For SSH_WRITE_PENDING, your invocation of poll( should include POLLOUT))
func (s *Session) GetPollFlags() int {
	return int(C.ssh_get_poll_flags(s.ptr))
}

// GetPubkey()
//
// Get the server public key from a session.
func (s *Session) GetPubkey() (*Key, error) {
	var key *C.ssh_key
	err := commonError(C.ssh_get_publickey(s.ptr, key))
	if err != nil {
		return nil, err
	}
	return &Key{*key}, nil
}

// GetServerBanner()
//
// get the server banner
func (s *Session) GetServerBanner() string {
	banner := C.ssh_get_serverbanner(s.ptr)
	if banner == nil {
		return ""
	}
	return C.GoString(banner)
}

// GetStatus()
//
// Get session status.
//
// return A bitmask including SSH_CLOSED, SSH_READ_PENDING, SSH_WRITE_PENDING or
// SSH_CLOSED_ERROR which respectively means the session is closed, has data to
// read on the connection socket and session was closed due to an error.
func (s *Session) GetStatus() int {
	return int(C.ssh_get_status(s.ptr))
}

// GetVersion()
//
// Get the protocol version of the session.
//
// return 1 or 2, for ssh1 or ssh2, < 0 on error.
func (s *Session) GetVersion() int {
	return int(C.ssh_get_version(s.ptr))
}

// IsBlocking()
//
// Return the blocking mode of libssh.
func (s *Session) IsBlocking() bool {
	return C.ssh_is_blocking(s.ptr) == 1
}

// IsConnected()
//
// Check if we are connected.
func (s *Session) IsConnected() bool {
	return C.ssh_is_connected(s.ptr) == 1
}

// IsServerKnown()
//
// Check if the server is known.
// Checks the user's known host file for a previous connection to the current server.
//
// return:
// SSH_SERVER_KNOWN_OK: The server is known and has not changed.
// SSH_SERVER_KNOWN_CHANGED: The server key has changed. Either you are under attack or the administrator changed the key. You HAVE to warn the user about a possible attack.
// SSH_SERVER_FOUND_OTHER: The server gave use a key of a type while we had an other type recorded. It is a possible attack.
// SSH_SERVER_NOT_KNOWN: The server is unknown. User should confirm the MD5 is correct.
// SSH_SERVER_FILE_NOT_FOUND: The known host file does not exist. The host is thus unknown. File will be created if host key is accepted.
// SSH_SERVER_ERROR: Some error happened.
func (s *Session) IsServerKnown() int {
	return int(C.ssh_is_server_known(s.ptr))
}

// Duplicate()
//
// Duplicate the options of a session structure.
// If you make several sessions with the same options this is useful. You cannot
// use twice the same option structure in ssh_session_connect.
//
func (s *Session) Duplicate() (*Session, error) {
	var ptr *C.ssh_session
	if C.ssh_options_copy(s.ptr, ptr) == 0 {
		return &Session{*ptr}, nil
	}
	return nil, errors.New("Unable to duplicate session")
}

// GetOption()
//
// This function can get ssh options, it does not support all options provided
// for ssh options set, but mostly those which a user-space program may care
// about having trusted the ssh driver to infer these values from underlaying
// configuration files.
//
// optionType:
// The option type to get. This could be one of the following:
//
// * SSH_OPTIONS_HOST: The hostname or ip address to connect to (const char *).
// * SSH_OPTIONS_USER: The username for authentication (const char *).
// when not explicitly set this will be inferred from the ~/.ssh/config file.
//
// * SSH_OPTIONS_IDENTITY: Set the identity file name (const char *,format
// string).
// By default identity, id_dsa and id_rsa are checked.
// The identity file used authenticate with public key. It may include "%s"
// which will be replaced by the user home directory.
//
// * SSH_OPTIONS_ADD_IDENTITY: Add a new identity file (const char *,format
// string) to the identity list.
// By default identity, id_dsa and id_rsa are checked.
// The identity used authenticate with public key will be prepended to the list.
// It may include "%s" which will be replaced by the user home directory.
//
// * SSH_OPTIONS_PROXYCOMMAND: Get the proxycommand necessary to log into the
// remote host. When not explicitly set, it will be read from the ~/.ssh/config
// file
func (s *Session) GetOption(optionType int) string {
	var option **C.char
	if C.ssh_options_get(s.ptr, C.enum_ssh_options_e(optionType), option) == SSH_OK {
		defer C.ssh_string_free_char(*option)
		return C.GoString(*option)
	}
	return ""
}

// GetPort()
//
// This function can get ssh the ssh port.
// It must only be used on a valid ssh session. This function is useful when the
// session options have been automatically inferred from the environment or
// configuration files and one
//
func (s *Session) GetPort() int {
	var port *C.uint
	if C.ssh_options_get_port(s.ptr, port) == SSH_OK {
		return int(*port)
	}
	return -1
}

// ParseConfig()
//
// Parse the ssh config file.
//
// This should be the last call of all options, it may overwrite options which
// are already set. It requires that the host name is already set with
// ssh_options_set_host().
//
// filename:
// The options file to use, if "" the default ~/.ssh/config will be used.
func (s *Session) ParseConfig(filename string) error {
	filename_cstr := C.CString(filename)
	defer C.free(unsafe.Pointer(filename_cstr))
	if C.ssh_options_parse_config(s.ptr, filename_cstr) == SSH_OK {
		return nil
	}
	return errors.New("Unable to parse ssh config")
}

// SetOption()
//
// This function can set all possible ssh options.
//
// SSH_OPTIONS_HOST: The hostname or ip address to connect to (const char *).
// SSH_OPTIONS_PORT: The port to connect to (unsigned int).
// SSH_OPTIONS_PORT_STR: The port to connect to (const char *).
// SSH_OPTIONS_FD: The file descriptor to use (socket_t).
//
// If you wish to open the socket yourself for a reason or another, set the
// file descriptor. Don't forget to set the hostname as the hostname is used as
// a key in the known_host mechanism.
// SSH_OPTIONS_BINDADDR: The address to bind the client to (const char *).
// SSH_OPTIONS_USER: The username for authentication (const char *).
//
// If the value is NULL, the username is set to the default username.
// SSH_OPTIONS_SSH_DIR: Set the ssh directory (const char *,format string).
//
// If the value is NULL, the directory is set to the default ssh directory.
//
// The ssh directory is used for files like known_hosts and identity (private and public
// key). It may include "%s" which will be replaced by the user home directory.
// SSH_OPTIONS_KNOWNHOSTS: Set the known hosts file name (const char *,format string).
//
// If the value is NULL, the directory is set to the default known hosts file, normally ~/.ssh/known_hosts.
//
// The known hosts file is used to certify remote hosts are genuine. It may include "%s"
// which will be replaced by the user home directory.
// SSH_OPTIONS_IDENTITY: Set the identity file name (const char *,format string).
//
// By default identity, id_dsa and id_rsa are checked.
//
// The identity file used authenticate with public key. It may include "%s" which will be replaced by the user home directory.
// SSH_OPTIONS_TIMEOUT: Set a timeout for the connection in seconds (long).
// SSH_OPTIONS_TIMEOUT_USEC: Set a timeout for the connection in micro seconds (long).
// SSH_OPTIONS_SSH1: Allow or deny the connection to SSH1 servers (int, 0 is false).
// SSH_OPTIONS_SSH2: Allow or deny the connection to SSH2 servers (int, 0 is false).
// SSH_OPTIONS_LOG_VERBOSITY: Set the session logging verbosity (int).
//
// The verbosity of the messages. Every log smaller or equal to verbosity will be shown.
// SSH_LOG_NOLOG: No logging
// SSH_LOG_RARE: Rare conditions or warnings
// SSH_LOG_ENTRY: API-accessible entrypoints
// SSH_LOG_PACKET: Packet id and size
// SSH_LOG_FUNCTIONS: Function entering and leaving
// SSH_OPTIONS_LOG_VERBOSITY_STR: Set the session logging verbosity (const char *).
//
// The verbosity of the messages. Every log smaller or equal to verbosity will be shown.
// SSH_LOG_NOLOG: No logging
// SSH_LOG_RARE: Rare conditions or warnings
// SSH_LOG_ENTRY: API-accessible entrypoints
// SSH_LOG_PACKET: Packet id and size
// SSH_LOG_FUNCTIONS: Function entering and leaving
// See the corresponding numbers in libssh.h.
//
// During ssh_connect(), libssh will call the callback with status from 0.0 to 1.0.
// SSH_OPTIONS_STATUS_ARG: Set the status argument which should be passed to the status callback (generic pointer).
// SSH_OPTIONS_CIPHERS_C_S: Set the symmetric cipher client to server (const char *, comma-separated list).
// SSH_OPTIONS_CIPHERS_S_C: Set the symmetric cipher server to client (const char *, comma-separated list).
// SSH_OPTIONS_KEY_EXCHANGE: Set the key exchange method to be used (const char *, comma-separated list). ex: "ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
// SSH_OPTIONS_HOSTKEYS: Set the preferred server host key types (const char *, comma-separated list). ex: "ssh-rsa,ssh-dss,ecdh-sha2-nistp256"
// SSH_OPTIONS_COMPRESSION_C_S: Set the compression to use for client to server communication (const char *, "yes", "no" or a specific algorithm name if needed ("zlib","zlib@openssh.com","none").
// SSH_OPTIONS_COMPRESSION_S_C: Set the compression to use for server to client communication (const char *, "yes", "no" or a specific algorithm name if needed ("zlib","zlib@openssh.com","none").
// SSH_OPTIONS_COMPRESSION: Set the compression to use for both directions communication (const char *, "yes", "no" or a specific algorithm name if needed ("zlib","zlib@openssh.com","none").
// SSH_OPTIONS_COMPRESSION_LEVEL: Set the compression level to use for zlib functions. (int, value from 1 to 9, 9 being the most efficient but slower).
// SSH_OPTIONS_STRICTHOSTKEYCHECK: Set the parameter StrictHostKeyChecking to avoid asking about a fingerprint (int, 0 = false).
// SSH_OPTIONS_PROXYCOMMAND: Set the command to be executed in order to connect to server (const char *).
// SSH_OPTIONS_GSSAPI_SERVER_IDENTITY Set it to specify the GSSAPI server identity that libssh should expect when connecting to the server (const char *).
// SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY Set it to specify the GSSAPI client identity that libssh should expect when connecting to the server (const char *).
// SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS Set it to specify that GSSAPI should delegate credentials to the server (int, 0 = false).

func (s *Session) SetOption(optionType int, value interface{}) error {
	var v unsafe.Pointer
	switch optionType {
	default:
		val, ok := value.(string)
		if !ok {
			return errors.New("Illegal value for setting option, requires string")
		}
		v = unsafe.Pointer(C.CString(val))
		defer C.free(v)
	case SSH_OPTIONS_PORT:
		val, ok := value.(int)
		if !ok {
			if _, ok = value.(string); ok {
				optionType = SSH_OPTIONS_PORT_STR
				return s.SetOption(SSH_OPTIONS_PORT_STR, value)
			}
			return errors.New("Illegal value for setting option, requires string(int)")
		}
		v = unsafe.Pointer(&val)
	case SSH_OPTIONS_FD: // socket_t
		val, ok := value.(int)
		if !ok {
			return errors.New("Illegal value for setting option, requires int")
		}
		_val := C.socket_t(val)
		v = unsafe.Pointer(&_val)
	case SSH_OPTIONS_TIMEOUT, SSH_OPTIONS_TIMEOUT_USEC: // long
		if val_int, ok := value.(int); ok {
			_v := C.long(val_int)
			v = unsafe.Pointer(&_v)
		} else if val_uint, ok := value.(uint); ok {
			_v := C.long(val_uint)
			v = unsafe.Pointer(&_v)
		} else if val_i64, ok := value.(int64); ok {
			_v := C.long(val_i64)
			v = unsafe.Pointer(&_v)
		} else if val_u64, ok := value.(uint64); ok {
			_v := C.long(val_u64)
			v = unsafe.Pointer(&_v)
		} else {
			return errors.New("Illegal value for setting option, requires int/uint/int64/uint64")
		}
	case SSH_OPTIONS_SSH1, SSH_OPTIONS_SSH2: // int or bool -> false
		if val_int, ok := value.(int); ok {
			v = unsafe.Pointer(&val_int)
		} else if val_bool, ok := value.(bool); ok && !val_bool {
			val := 0
			v = unsafe.Pointer(&val)
		} else {
			return errors.New("Illegal value for setting option, requires int/false")
		}
	case SSH_OPTIONS_LOG_VERBOSITY,
		SSH_OPTIONS_COMPRESSION_LEVEL,
		SSH_OPTIONS_STRICTHOSTKEYCHECK,
		SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
		if val, ok := value.(int); !ok {
			return errors.New("Illegal value for setting option, requires int")
		} else {
			v = unsafe.Pointer(&val)
		}
	}

	if C.ssh_options_set(s.ptr, C.enum_ssh_options_e(optionType), v) != SSH_OK {
		return errors.New("Unable to set option")
	}
	return nil
}

// SendDebugMessage()
//
// Send a debug message.
//
// message:
// Data to be sent
//
// alwaysDisplay:
//	Message SHOULD be displayed by the server. It SHOULD NOT be displayed unless debugging information has been explicitly requested
func (s *Session) SendDebugMessage(message string, alwaysDisplay bool) error {
	msg := C.CString(message)
	defer C.free(unsafe.Pointer(msg))
	var display C.int = 0
	if alwaysDisplay {
		display = 1
	}
	if C.ssh_send_debug(s.ptr, msg, display) != SSH_OK {
		return errors.New("send debug messaged failed")
	}
	return nil
}

// SendIgnoreMessage()
//
// Send a message that should be ignored.
func (s *Session) SendIgnoreMessage(message string) error {
	msg := C.CString(message)
	defer C.free(unsafe.Pointer(msg))
	if C.ssh_send_ignore(s.ptr, msg) != SSH_OK {
		return errors.New("send ignored messaged failed")
	}
	return nil
}

// SetBlocking()
//
// Set the session in blocking/nonblocking mode
func (s *Session) SetBlocking(blocking bool) {
	var value C.int = 0
	if blocking {
		value = 1
	}
	C.ssh_set_blocking(s.ptr, value)
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

// Set the session data counters.
//
// This functions sets the counter structures to be used to calculate data which
// comes in and goes out through the session at different levels.
//
// scounter:
// Counter for byte data handled by the session sockets.
//
// rcounter:
// Counter for byte and packet data handled by the session, prior compression
// and SSH overhead.

func (s *Session) SetCounter(scounter, rcounter Counter) {
	C.ssh_set_counters(s.ptr, scounter.toCCounter(), rcounter.toCCounter())
}

// Tell the session it has an exception to catch on the file descriptor.
func (s *Session) SetFdExcept() {
	C.ssh_set_fd_except(s.ptr)
}

// Tell the session it has data to read on the file descriptor without blocking.
func (s *Session) SetFdToRead() {
	C.ssh_set_fd_toread(s.ptr)
}

// Tell the session it may write to the file descriptor without blocking.
func (s *Session) SetFdToWrite() {
	C.ssh_set_fd_towrite(s.ptr)
}

// Disconnect impolitely from a remote host by closing the socket.
//
// Suitable if you forked and want to destroy this session.
func (s *Session) SilentDisconnect() {
	C.ssh_silent_disconnect(s.ptr)
}

// Write the current server as known in the known hosts file.
//
// This will create the known hosts file if it does not exist. You generaly use
// it when ssh_is_server_known() answered SSH_SERVER_NOT_KNOWN.
func (s *Session) WriteKnownHost() error {
	if C.ssh_write_knownhost(s.ptr) != SSH_OK {
		return errors.New("Unable to save current server as in known list")
	}
	return nil
}

// auth-stuff

// Get available authentication methods from the server.
// This requires the function ssh_userauth_none() to be called before the methods
// are available. The server MAY return a list of methods that may continue.
//
// Returns
//  A bitfield of the fllowing values:
//  SSH_AUTH_METHOD_PASSWORD
//  SSH_AUTH_METHOD_PUBLICKEY
//  SSH_AUTH_METHOD_HOSTBASED
//  SSH_AUTH_METHOD_INTERACTIVE
func (s *Session) GetAvailableAuthMethodsFromServer() int {
	return int(C.ssh_userauth_list(s.ptr, nil))
}

// Try to do public key authentication with ssh agent.
//
// Note:
// Most server implementations do not permit changing the username during
// authentication. The username should only be set with ssh_options_set() only
// before you connect to the server.
func (s *Session) AuthWithUser(name string) error {
	username := C.CString(name)
	defer C.free(unsafe.Pointer(username))
	return authError(C.ssh_userauth_agent(s.ptr, username))
}

// Try to authenticate through the "gssapi-with-mic" method.
func (s *Session) AuthWithGassapi() error {
	return authError(C.ssh_userauth_gssapi(s.ptr))
}

// Try to authenticate through the "none" method.
func (s *Session) AuthWithNone() error {
	return authError(C.ssh_userauth_none(s.ptr, nil))
}

// Try to authenticate by password
//
// This authentication method is normally disabled on SSHv2 server. You should
// use keyboard-interactive mode.
//
// The 'password' value MUST be encoded UTF-8. It is up to the server how to
// interpret the password and validate it against the password database.
// However, if you read the password in some other encoding, you MUST convert
// the password to UTF-8.
//
func (s *Session) AuthWithPassword(password string) error {
	password_cstr := C.CString(password)
	defer C.free(unsafe.Pointer(password_cstr))
	return authError(C.ssh_userauth_password(s.ptr, nil, password_cstr))
}

// Authenticate with public/private key or certificate.
func (s *Session) AuthWithPubkey(privateKey *Key) error {
	return authError(C.ssh_userauth_publickey(s.ptr, nil, privateKey.key))
}

// Tries to automatically authenticate with public key and "none".
//
// It may fail, for instance it doesn't ask for a password and uses a default
// asker for passphrases (in case the private key is encrypted)
//
// passphrase:
// Use this passphrase to unlock the privatekey. Use NULL if you don't want to
// use a passphrase or the user should be asked.
func (s *Session) AuthWithPubkeyAutomatically(passphrase string) error {
	var passphrase_cstr *C.char
	if passphrase != "" {
		passphrase_cstr = C.CString(passphrase)
		defer C.free(unsafe.Pointer(passphrase_cstr))
	}
	return authError(C.ssh_userauth_publickey_auto(s.ptr, nil, passphrase_cstr))
}

// Try to authenticate with the given public key.
//
// To avoid unnecessary processing and user interaction, the following method is
// provided for querying whether authentication using the 'pubkey' would be
// possible
func (s *Session) TryAuthWithPubkey(pubkey *Key) error {
	return authError(C.ssh_userauth_try_publickey(s.ptr, nil, pubkey.key))
}

func (s *Session) SetKeyboardInteractiveMode() error {
	return authError(C.ssh_userauth_kbdint(s.ptr, nil, nil))
}
