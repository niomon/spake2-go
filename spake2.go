package spake2go

import (
	// "errors"

	"authcore.io/spake2go/internal/ciphersuite"
)

// SPAKE2 defines an initial state for SPAKE2. One could execute `StartClient` or `StartServer` to
// create an intermediate state for handshaking, or execute `ComputeVerifier` to compute the
// verifier from password and salt.
type SPAKE2 struct {
	suite ciphersuite.CipherSuite
}

// SPAKE2Plus defines an initial state for SPAKE2+. One could execute `StartClient` or
// `StartServer` to create an intermediate state for handshaking, or execute `ComputeVerifier` to
// compute the verifier from identities of the client and server, as well as password and salt.
type SPAKE2Plus struct {
	suite ciphersuite.CipherSuite
}

// ClientState defines an intermediate state for SPAKE2. The `Finish` method takes a message from
// the server and verifies if it is valid.
type ClientState struct {
	suite ciphersuite.CipherSuite
}

// ServerState defines an intermediate state for SPAKE2. The `Finish` method takes a message from
// the client and verifies if it is valid.
type ServerState struct {
	suite ciphersuite.CipherSuite
}

// ClientPlusState defines an intermediate state for SPAKE2. The `Finish` method takes a message
// from the server and verifies if it is valid.
type ClientPlusState struct {
	suite ciphersuite.CipherSuite
}

// ServerPlusState defines an intermediate state for SPAKE2. The `Finish` method takes a message
// from the client and verifies if it is valid.
type ServerPlusState struct {
	suite ciphersuite.CipherSuite
}

// ClientSharedSecret defines a shared secret. `GetConfirmation` gets the confirmation message,
// `Verify` verifies the incoming confirmation message and `Bytes` gets the shared secret of the
// protocol.
type ClientSharedSecret struct {
	suite ciphersuite.CipherSuite
}

// ServerSharedSecret defines a shared secret. `GetConfirmation` gets the confirmation message,
// `Verify` verifies the incoming confirmation message and `Bytes` gets the shared secret of the
// protocol.
type ServerSharedSecret struct {
	suite ciphersuite.CipherSuite
}

// Hkdf returns a struct of the options for HKDF.
func Hkdf(AAD []byte) *ciphersuite.Hkdf {
	return &ciphersuite.Hkdf{AAD}
}

// Scrypt returns a struct of the options for scrypt.
func Scrypt(N, R, P uint) *ciphersuite.Scrypt {
	return &ciphersuite.Scrypt{N, R, P}
}

// Ed25519Sha256HkdfHmacScrypt returns a cipher suite for SPAKE2 (or SPAKE2+).
func Ed25519Sha256HkdfHmacScrypt(hkdf *ciphersuite.Hkdf, scrypt *ciphersuite.Scrypt) *ciphersuite.Ed25519Sha256HkdfHmacScrypt {
	return &ciphersuite.Ed25519Sha256HkdfHmacScrypt{
		Hkdf:   hkdf,
		Scrypt: scrypt,
	}
}

// NewSPAKE2 creates a new instance of SPAKE2.
func NewSPAKE2(suite ciphersuite.CipherSuite) (*SPAKE2, error) {
	return &SPAKE2{suite}, nil
}

// NewSPAKE2Plus creates a new instance of SPAKE2+.
func NewSPAKE2Plus(suite ciphersuite.CipherSuite) (*SPAKE2Plus, error) {
	return &SPAKE2Plus{suite}, nil
}

// StartClient initializes a new client for SPAKE2. Returns a SPAKE2 client state and message.
func (s SPAKE2) StartClient(clientIdentity, serverIdentity, password, salt []byte) (*ClientState, []byte, error) {

	return &ClientState{s.suite}, []byte{}, nil
}

// StartServer initializes a new server for SPAKE2. Returns a SPAKE2 server state and message.
func (s SPAKE2) StartServer(clientIdentity, serverIdentity, verifier []byte) (*ServerState, []byte, error) {
	return &ServerState{s.suite}, []byte{}, nil
}

// ComputeVerifier computes a verifier for SPAKE2 from password and salt.
func (s SPAKE2) ComputeVerifier(password, salt []byte) ([]byte, error) {
	return []byte{}, nil
}

// StartClient initializes a new client for SPAKE2+. Returns a SPAKE2+ client state and message.
func (s SPAKE2Plus) StartClient(clientIdentity, serverIdentity, password, salt []byte) (*ClientPlusState, []byte, error) {
	return &ClientPlusState{s.suite}, []byte{}, nil
}

// StartServer initializes a new server for SPAKE2+. Returns a SPAKE2+ server state and message.
func (s SPAKE2Plus) StartServer(clientIdentity, serverIdentity, verifierW0 []byte, verifierL []byte) (*ServerPlusState, []byte, error) {
	return &ServerPlusState{s.suite}, []byte{}, nil
}

// ComputeVerifier computes a verifier for SPAKE2 from password, salt and identities of the client
// and server.
func (s SPAKE2Plus) ComputeVerifier(password, salt, clientIdentity, serverIdentity []byte) ([]byte, error) {
	return []byte{}, nil
}

// Finish verifies an incomingMessage from the server and returns a shared secret if it is
// validated.
func (s ClientState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	return &ClientSharedSecret{s.suite}, nil
}

// Finish verifies an incomingMessage from the client and returns a shared secret if it is
// validated.
func (s ServerState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	return &ServerSharedSecret{s.suite}, nil
}

// Finish verifies an incomingMessage from the server and returns a shared secret if it is
// validated.
func (s ClientPlusState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	return &ClientSharedSecret{s.suite}, nil
}

// Finish verifies an incomingMessage from the client and returns a shared secret if it is
// validated.
func (s ServerPlusState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	return &ServerSharedSecret{s.suite}, nil
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s ClientSharedSecret) GetConfirmation() []byte {
	return []byte{}
}

// Verify verifies an incoming confirmation message.
func (s ClientSharedSecret) Verify(incomingConfirmation []byte) error {
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ClientSharedSecret) Bytes() []byte {
	return []byte{}
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s ServerSharedSecret) GetConfirmation() []byte {
	return []byte{}
}

// Verify verifies an incoming confirmation message.
func (s ServerSharedSecret) Verify(incomingConfirmation []byte) error {
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ServerSharedSecret) Bytes() []byte {
	return []byte{}
}

// func (s ServerSharedSecret) SetBytes(b []bytes) bool {}
