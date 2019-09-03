package spake2go

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSPAKE2(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Hkdf([]byte{}), Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	expectedVerifier, err := hex.DecodeString("0ec6b7483ed26e08802b41f4032086a017d0fbc866e3af79bf38eff06efd0bb2")
	if !assert.NoError(t, err) {
		return
	}

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}

	verifier, err := s.ComputeVerifier(password, salt)
	if !assert.Equal(t, expectedVerifier, verifier) {
		return
	}

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifier)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA := sharedSecretA.GetConfirmation()
	confirmationB := sharedSecretB.GetConfirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
}

func TestSPAKE2Plus(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Hkdf([]byte{}), Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	expectedVerifierW0, err := hex.DecodeString("7329b4dddcffdf5d3942a223ee58fa39")
	if !assert.NoError(t, err) {
		return
	}
	expectedVerifierL, err := hex.DecodeString("3f3ecdc0aa6298b17b9bfaf4c4c047400a21f0ccfd8c223bf2f2a883edfc6ac5")
	if !assert.NoError(t, err) {
		return
	}

	// Creates a SPAKE2+ instance
	s, err := NewSPAKE2Plus(suite)
	if !assert.NoError(t, err) {
		return
	}

	verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)
	if !assert.Equal(t, expectedVerifierW0, verifierW0) {
		return
	}
	if !assert.Equal(t, expectedVerifierL, verifierL) {
		return
	}

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifierW0, verifierL)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA := sharedSecretA.GetConfirmation()
	confirmationB := sharedSecretB.GetConfirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
}
