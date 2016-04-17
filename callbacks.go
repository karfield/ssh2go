package libssh

type ServerAuthentication interface {
	AuthWithPassword(session *Session, user, password string) bool
	AuthWithoutPassword(session *Session, user string) bool
	AuthGssapiWithMic(session *Session, user, principal string) bool
	AuthWithPubkey(session *Session, user string, pubkey *Key, signatureState int) bool
}
