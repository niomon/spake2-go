package spake2go

import (
	"bytes"
	"encoding/binary"

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
	suite          ciphersuite.CipherSuite
	x              ciphersuite.Scalar
	clientIdentity []byte
	serverIdentity []byte
	verifier       []byte
	msgT           []byte
	aad            []byte
}

// ServerState defines an intermediate state for SPAKE2. The `Finish` method takes a message from
// the client and verifies if it is valid.
type ServerState struct {
	suite          ciphersuite.CipherSuite
	y              ciphersuite.Scalar
	clientIdentity []byte
	serverIdentity []byte
	verifier       []byte
	msgS           []byte
	aad            []byte
}

// ClientPlusState defines an intermediate state for SPAKE2. The `Finish` method takes a message
// from the server and verifies if it is valid.
type ClientPlusState struct {
	suite          ciphersuite.CipherSuite
	x              ciphersuite.Scalar
	clientIdentity []byte
	serverIdentity []byte
	verifierW0     []byte
	verifierW1     []byte
	msgX           []byte
	aad            []byte
}

// ServerPlusState defines an intermediate state for SPAKE2. The `Finish` method takes a message
// from the client and verifies if it is valid.
type ServerPlusState struct {
	suite          ciphersuite.CipherSuite
	y              ciphersuite.Scalar
	clientIdentity []byte
	serverIdentity []byte
	verifierW0     []byte
	verifierL      []byte
	msgY           []byte
	aad            []byte
}

// ClientSharedSecret defines a shared secret. `GetConfirmation` gets the confirmation message,
// `Verify` verifies the incoming confirmation message and `Bytes` gets the shared secret of the
// protocol.
type ClientSharedSecret struct {
	suite        ciphersuite.CipherSuite
	transcript   []byte
	sharedSecret []byte
	kcA          []byte
	kcB          []byte
}

// ServerSharedSecret defines a shared secret. `GetConfirmation` gets the confirmation message,
// `Verify` verifies the incoming confirmation message and `Bytes` gets the shared secret of the
// protocol.
type ServerSharedSecret struct {
	suite        ciphersuite.CipherSuite
	transcript   []byte
	sharedSecret []byte
	kcA          []byte
	kcB          []byte
}

// Hkdf returns a struct of the options for HKDF.
func Hkdf(AAD []byte) *ciphersuite.Hkdf {
	return &ciphersuite.Hkdf{AAD}
}

// Scrypt returns a struct of the options for scrypt.
func Scrypt(N, R, P int) *ciphersuite.Scrypt {
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

func (s SPAKE2) startClient(clientIdentity, serverIdentity, password, salt, aad []byte, x ciphersuite.Scalar) (*ClientState, []byte, error) {
	w, err := s.computeW(password, salt)
	if err != nil {
		return nil, []byte{}, err
	}
	T := s.suite.Curve().P().ScalarMul(x).Add(s.suite.Curve().M().ScalarMul(w))
	TBytes := T.Bytes()
	return &ClientState{s.suite, x, clientIdentity, serverIdentity, w.Bytes(), TBytes, aad}, TBytes, nil
}

// StartClient initializes a new client for SPAKE2. Returns a SPAKE2 client state and message.
func (s SPAKE2) StartClient(clientIdentity, serverIdentity, password, salt, aad []byte) (*ClientState, []byte, error) {
	x := s.suite.Curve().RandomScalar()
	return s.startClient(clientIdentity, serverIdentity, password, salt, aad, x)
}

func (s SPAKE2) startServer(clientIdentity, serverIdentity, verifier, aad []byte, y ciphersuite.Scalar) (*ServerState, []byte, error) {
	w, err := s.suite.Curve().NewScalar(verifier)
	if err != nil {
		return nil, []byte{}, err
	}
	S := s.suite.Curve().P().ScalarMul(y).Add(s.suite.Curve().N().ScalarMul(w))
	SBytes := S.Bytes()
	return &ServerState{s.suite, y, clientIdentity, serverIdentity, verifier, SBytes, aad}, SBytes, nil
}

// StartServer initializes a new server for SPAKE2. Returns a SPAKE2 server state and message.
func (s SPAKE2) StartServer(clientIdentity, serverIdentity, verifier, aad []byte) (*ServerState, []byte, error) {
	y := s.suite.Curve().RandomScalar()
	return s.startServer(clientIdentity, serverIdentity, verifier, aad, y)
}

func (s SPAKE2) computeW(password, salt []byte) (ciphersuite.Scalar, error) {
	wBytes, err := s.suite.Mhf(password, salt)
	if err != nil {
		return nil, err
	}
	return s.suite.Curve().NewScalar(wBytes)
}

// ComputeVerifier computes a verifier for SPAKE2 from password and salt.
func (s SPAKE2) ComputeVerifier(password, salt []byte) ([]byte, error) {
	w, err := s.computeW(password, salt)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// StartClient initializes a new client for SPAKE2+. Returns a SPAKE2+ client state and message.
func (s SPAKE2Plus) StartClient(clientIdentity, serverIdentity, password, salt, aad []byte) (*ClientPlusState, []byte, error) {
	w0, w1, err := s.computeW0W1(password, salt, clientIdentity, serverIdentity)
	if err != nil {
		return nil, []byte{}, err
	}
	x := s.suite.Curve().RandomScalar()
	msgX := s.suite.Curve().P().ScalarMul(x).Add(s.suite.Curve().M().ScalarMul(w0))
	msgXBytes := msgX.Bytes()
	return &ClientPlusState{s.suite, x, clientIdentity, serverIdentity, w0.Bytes(), w1.Bytes(), msgXBytes, aad}, msgXBytes, nil
}

// StartServer initializes a new server for SPAKE2+. Returns a SPAKE2+ server state and message.
func (s SPAKE2Plus) StartServer(clientIdentity, serverIdentity, verifierW0, verifierL, aad []byte) (*ServerPlusState, []byte, error) {
	y := s.suite.Curve().RandomScalar()
	w0, err := s.suite.Curve().NewScalar(append([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), verifierW0[:16]...))
	if err != nil {
		return nil, []byte{}, err
	}
	msgY := s.suite.Curve().P().ScalarMul(y).Add(s.suite.Curve().N().ScalarMul(w0))
	msgYBytes := msgY.Bytes()
	return &ServerPlusState{s.suite, y, clientIdentity, serverIdentity, verifierW0, verifierL, msgYBytes, aad}, msgYBytes, nil
}

func (s SPAKE2Plus) computeW0W1(clientIdentity, serverIdentity, password, salt []byte) ([]byte, []byte, error) {
	wBytes, err := s.suite.Mhf(
		concat(password, clientIdentity, serverIdentity),
		salt,
	)
	if err != nil {
		return nil, nil, err
	}
	w0, err := s.suite.Curve().NewScalar(append([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), wBytes[:16]...))
	if err != nil {
		return nil, nil, err
	}
	w1, err := s.suite.Curve().NewScalar(append([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), wBytes[16:]...))
	if err != nil {
		return nil, nil, err
	}
	return w0.Bytes(), w1.Bytes(), nil
}

// ComputeVerifier computes a verifier for SPAKE2 from password, salt and identities of the client
// and server.
func (s SPAKE2Plus) ComputeVerifier(password, salt, clientIdentity, serverIdentity []byte) ([]byte, []byte, error) {
	w0, w1, err := s.computeW0W1(clientIdentity, serverIdentity, password, salt)
	if err != nil {
		return nil, nil, err
	}

	w1Scalar, err := s.suite.Curve().NewScalar(w1)
	if err != nil {
		return nil, nil, err
	}

	P := s.suite.Curve().P()
	L := P.ScalarMul(w1Scalar)
	return unpad(w0), unpad(L.Bytes()), nil
}

func concat(bytesArray ...[]byte) []byte {
	result := []byte{}
	for _, bytes := range bytesArray {
		if len(bytes) > 0 {
			bytesLen := make([]byte, 8)
			binary.LittleEndian.PutUint64(bytesLen, uint64(len(bytes)))
			result = append(result, bytesLen...)
			result = append(result, bytes...)
		}
	}
	return result
}

func unpad(bytesArray []byte) []byte {
	return bytes.TrimLeft(bytesArray, "\x00")
}
