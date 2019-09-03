package spake2go

import (
	// "encoding/hex"
	"testing"
	// "github.com/stretchr/testify/assert"
)

func TestXXX(t *testing.T) {
	suite := Ed25519Sha256HkdfHmacScrypt(Hkdf([]byte{}), Scrypt(16, 1, 1))
	t.Log(suite)
}

// func TestSPAKE2(t *testing.T) {
// 	// Defines the cipher suite
// 	suite := Ed25519Sha256HkdfHmacScrypt(Hkdf([]byte{}), Scrypt(16, 1, 1))

// 	clientIdentity := []byte("client")
// 	serverIdentity := []byte("server")
// 	password := []byte("password")
// 	salt := []byte("NaCl")
// 	expectedVerifier, err := hex.DecodeString("0ec6b7483ed26e08802b41f4032086a017d0fbc866e3af79bf38eff06efd0bb2")
// 	if !assert.NoError(t, err) {
// 		return
// 	}

// 	// Creates a SPAKE2 instance
// 	s, err := NewSPAKE2(suite)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	t.Log(s, err)

// 	verifier, err := s.ComputeVerifier(password, salt)
// 	t.Log(verifier, err)
// 	if !assert.Equal(t, expectedVerifier, verifier) {
// 		return
// 	}

// 	// Creates a SPAKE2 client and a SPAKE2 server.
// 	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, password, salt)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	t.Log(stateA, messageA, err)

// 	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifier)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	t.Log(stateB, messageB, err)

// 	// A and B verify the incoming message from each other.
// 	sharedSecretA, err := stateA.Finish(messageB)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	t.Log(sharedSecretA, err)

// 	sharedSecretB, err := stateB.Finish(messageA)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	t.Log(sharedSecretB, err)

// 	// A and B verify the confirmation message from each other.
// 	confirmationA := sharedSecretA.GetConfirmation()
// 	t.Log(confirmationA)
// 	confirmationB := sharedSecretB.GetConfirmation()
// 	t.Log(confirmationB)

// 	err = sharedSecretA.Verify(confirmationB)
// 	if !assert.NoError(t, err) {
// 		return
// 	}
// 	err = sharedSecretB.Verify(confirmationA)
// 	if !assert.NoError(t, err) {
// 		return
// 	}

// 	// A and B have a common shared secret.
// 	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
// }
