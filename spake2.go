package spake2

import (
	"spake2/internal"
)

type SPAKE2 struct {
	suite internal.CipherSuite
}
type SPAKE2Plus struct {
	suite internal.CipherSuite
}

type ClientState struct {
	suite internal.CipherSuite
}
type ServerState struct {
	suite internal.CipherSuite
}
type ClientPlusState struct {
	suite internal.CipherSuite
}
type ServerPlusState struct {
	suite internal.CipherSuite
}

type ClientSharedSecret struct {
	suite internal.CipherSuite
}
type ServerSharedSecret struct {
	suite internal.CipherSuite
}

func NewSPAKE2(options interface{}) (*SPAKE2, error) {
	return &SPAKE2{}, nil
}

func NewSPAKE2Plus(options interface{}) (*SPAKE2Plus, error) {
	return &SPAKE2Plus{}, nil
}

func (s SPAKE2) StartClient(clientIdentity, serverIdentity, password, salt []byte) (*ClientState, []byte, error) {
	return nil, []byte{}, nil
}

func (s SPAKE2) StartServer(clientIdentity, serverIdentity, verifier internal.Verifier) (*ServerState, []byte, error) {
	return nil, []byte{}, nil
}

func (s SPAKE2) ComputeVerifier(password, salt []byte) ([]byte, error) {
	return []byte{}, nil
}

func (s SPAKE2Plus) StartClient(clientIdentity, serverIdentity, password, salt []byte) (*ClientPlusState, []byte, error) {
	return nil, []byte{}, nil
}

func (s SPAKE2Plus) StartServer(clientIdentity, serverIdentity, verifier internal.Verifier) (*ServerPlusState, []byte, error) {
	return nil, []byte{}, nil
}

func (s SPAKE2Plus) ComputeVerifier(password, salt, clientIdentity, serverIdentity []byte) ([]byte, error) {
	return []byte{}, nil
}

func (s ClientState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	return nil, nil
}

func (s ServerState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	return nil, nil
}

func (s ClientPlusState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	return nil, nil
}

func (s ServerPlusState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	return nil, nil
}

func (s ClientSharedSecret) GetConfirmation() []byte {
	return []byte{}
}

func (s ClientSharedSecret) Verify(incomingConfirmation []byte) error {
	return nil
}

func (s ClientSharedSecret) Bytes() []byte {
	return []byte{}
}

func (s ServerSharedSecret) GetConfirmation() []byte {
	return []byte{}
}

func (s ServerSharedSecret) Verify(incomingConfirmation []byte) error {
	return nil
}

func (s ServerSharedSecret) Bytes() []byte {
	return []byte{}
}

// func (s ServerSharedSecret) SetBytes(b []bytes) bool {}
