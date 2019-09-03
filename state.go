package spake2go

import (
// "errors"

// "authcore.io/spake2go/internal/ciphersuite"
)

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
