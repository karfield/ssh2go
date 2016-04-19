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
	"unsafe"
)

type Key struct {
	key C.ssh_key
}

func NewKey() (Key, error) {
	k := Key{}
	k.key = C.ssh_key_new()
	if k.key == nil {
		return k, errors.New("Unable allocate a key")
	}
	return k, nil
}

// Import a base64 formated certificate from a memory c-string.
//
// certType:
// SSH_KEYTYPE_UNKNOWN
// SSH_KEYTYPE_DSS
// SSH_KEYTYPE_RSA
// SSH_KEYTYPE_RSA1
// SSH_KEYTYPE_ECDSA
// SSH_KEYTYPE_ED25519
// SSH_KEYTYPE_DSS_CERT01
// SSH_KEYTYPE_RSA_CERT01
func ImportFromBase64(base64Cert string, certType int) (Key, error) {
	base64Cert_cstr := CString(base64Cert)
	defer base64Cert_cstr.Free()
	key := Key{}
	if C.ssh_pki_import_cert_base64(base64Cert_cstr.Ptr, C.enum_ssh_keytypes_e(certType), &key.key) == SSH_OK {
		return key, nil
	}
	return key, errors.New("ssh_pki_import_cert_base64() != SSH_OK")
}

// Import a certificate from the given filename.
func ImportFromFile(certFile string) (Key, error) {
	certFile_cstr := CString(certFile)
	defer certFile_cstr.Free()
	var key *C.ssh_key
	if C.ssh_pki_import_cert_file(certFile_cstr.Ptr, key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("ssh_pki_import_cert_file != SSH_OK")
}

// import a base64 formated key from a memory c-string
//
// base64:
//	The c-string holding the base64 encoded key
// passphrase:
//  The passphrase to decrypt the key, or ""
func ImportPrivateKeyFromBase64(base64, passphrase string) (Key, error) {
	base64_cstr := CString(base64)
	defer base64_cstr.Free()
	var passphrase_cstr *C.char = nil
	if passphrase != "" {
		cstr := CString(passphrase)
		defer cstr.Free()
		passphrase_cstr = cstr.Ptr
	}
	var key *C.ssh_key
	if C.ssh_pki_import_privkey_base64(base64_cstr.Ptr, passphrase_cstr, nil, nil, key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("ssh_pki_import_privkey_base64() != SSH_OK")
}

func ImportPrivateKeyFromFile(filename, passphrase string) (Key, error) {
	filename_cstr := CString(filename)
	defer filename_cstr.Free()
	var passphrase_cstr *C.char = nil
	if passphrase != "" {
		cstr := CString(passphrase)
		defer cstr.Free()
		passphrase_cstr = cstr.Ptr
	}
	var key *C.ssh_key
	if C.ssh_pki_import_privkey_file(filename_cstr.Ptr, passphrase_cstr, nil, nil, key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("ssh_pki_import_privkey_file() != SSH_OK")
}

func ImportPublicKeyFromBase64(base64 string, keyType int) (Key, error) {
	base64_cstr := CString(base64)
	defer base64_cstr.Free()
	var key *C.ssh_key
	if C.ssh_pki_import_pubkey_base64(base64_cstr.Ptr, C.enum_ssh_keytypes_e(keyType), key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("ssh_pki_import_pubkey_base64() != SSH_OK")
}

func ImportPublicKeyFromFile(filename string) (Key, error) {
	filename_cstr := CString(filename)
	defer filename_cstr.Free()
	var key *C.ssh_key
	if C.ssh_pki_import_pubkey_file(filename_cstr.Ptr, key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("ssh_pki_import_pubkey_file() != SSH_OK")
}

// Allocates a buffer with the hash of the public key.
//
// This function allows you to get a hash of the public key. You can then print
// this hash in a human-readable form to the user so that he is able to verify
// it. Use ssh_get_hexa() or ssh_print_hexa() to display it.
//
// typ:
//  The type of the hash you want:
//  SSH_PUBLICKEY_HASH_SHA1
//  SSH_PUBLICKEY_HASH_MD5
//
func (k Key) Hash(typ int) ([]byte, error) {
	var hash **C.uchar
	var size *C.size_t
	if C.ssh_get_publickey_hash(k.key, C.enum_ssh_publickey_hash_type(typ), hash, size) < 0 {
		return nil, errors.New("Key hash error")
	}
	defer C.ssh_clean_pubkey_hash(hash)
	return copyData(*hash, *size), nil
}

// clean up the key and deallocate all existing keys
/*func (k Key) Clean() {
	C.ssh_key_clean(k.key)
}*/

// deallocate a SSH key
func (k Key) Free() {
	C.ssh_key_free(k.key)
}

// Compare keys if they are equal.
//
// what:
//  What part or type of the key do you want to compare
//   SSH_KEY_CMP_PUBLIC
//   SSH_KEY_CMP_PRIVATE
func (k Key) Compare(k2 Key, what int) bool {
	return C.ssh_key_cmp(k.key, k2.key, C.enum_ssh_keycmp_e(what)) == 0
}

// Check if the key is a private key.
func (k Key) IsPrivate() bool {
	return C.ssh_key_is_private(k.key) == 1
}

// Check if the key has/is a public key.
func (k Key) IsPublic() bool {
	return C.ssh_key_is_public(k.key) == 1
}

// Get the type of a ssh key:
// SSH_KEYTYPE_RSA
// SSH_KEYTYPE_DSS
// SSH_KEYTYPE_RSA1
// SSH_KEYTYPE_UNKNOWN
func (k Key) Type() int {
	return int(C.ssh_key_type(k.key))
}

func KeyTypeFromName(name string) int {
	name_cstr := CString(name)
	defer name_cstr.Free()
	return int(C.ssh_key_type_from_name(name_cstr.Ptr))
}

func KeyTypeString(typ int) string {
	s := C.ssh_key_type_to_char(C.enum_ssh_keytypes_e(typ))
	if s != nil {
		return C.GoString(s)
	}
	return "unknown"
}

func (k Key) TypeString() string {
	return KeyTypeString(k.Type())
}

// Copy the certificate part of a public key into a private key.
func (k Key) CopyCertToPrivateKey(privateKey Key) error {
	if C.ssh_pki_copy_cert_to_privkey(k.key, privateKey.key) != SSH_OK {
		return errors.New("ssh_pki_copy_cert_to_privkey error")
	}
	return nil
}

// Export a private key to a pem file on disk, or OpenSSH format for keytype
// ssh-ed25519.
//
// passphrase:
//  The passphrase to use to encrypt the key with or NULL. An empty
//  string means no passphrase.
//
// permFile:
//  The path where to store the pem file
func (k Key) ExportPrivateKeyToFile(passphrase, permFile string) error {
	var passphrase_cstr *C.char = nil
	if passphrase != "" {
		cstr := CString(passphrase)
		defer cstr.Free()
		passphrase_cstr = cstr.Ptr
	}
	filename := CString(permFile)
	defer filename.Free()
	if C.ssh_pki_export_privkey_file(k.key, passphrase_cstr, nil, nil, filename.Ptr) != SSH_OK {
		return errors.New("ssh_pki_export_privkey_file failed")
	}
	return nil
}

// Create a public key from a private key.
func (k Key) ExportAsPublicKey() (Key, error) {
	var key *C.ssh_key
	if C.ssh_pki_export_privkey_to_pubkey(k.key, key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("Unable to export as a public key")
}

// Convert a public key to a base64 encoded key.
func (k Key) ExportPubkeyBase64() string {
	var base64_cstr **C.char
	if C.ssh_pki_export_pubkey_base64(k.key, base64_cstr) == SSH_OK {
		defer C.free(unsafe.Pointer(*base64_cstr))
		return C.GoString(*base64_cstr)
	}
	return ""
}

// Generates a keypair.
//
// keyType:
// SSH_KEYTYPE_UNKNOWN
// SSH_KEYTYPE_DSS
// SSH_KEYTYPE_RSA
// SSH_KEYTYPE_RSA1
// SSH_KEYTYPE_ECDSA
// SSH_KEYTYPE_ED25519
// SSH_KEYTYPE_DSS_CERT01
// SSH_KEYTYPE_RSA_CERT01
//
// parameter:
//  Parameter to the creation of key: rsa : length of the key in bits (e.g.
//  1024, 2048, 4096) dsa : length of the key in bits (e.g. 1024, 2048, 3072)
//  ecdsa : bits of the key (e.g. 256, 384, 512)
//
// Warning:
//  Generating a key pair may take some time.
func GenerateKeyPair(keyType, parameter int) (Key, error) {
	var key *C.ssh_key
	if C.ssh_pki_generate(C.enum_ssh_keytypes_e(keyType), C.int(parameter), key) == SSH_OK {
		return Key{*key}, nil
	}
	return Key{}, errors.New("Unable to gernerate key pair")
}
