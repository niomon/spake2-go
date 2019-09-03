package spake2go

import (
// "errors"

// "authcore.io/spake2go/internal/ciphersuite"
)

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
