package spake2

import (
	"bytes"
	"errors"

	"github.com/niomon/spake2-go/internal/ciphersuite"
)

func confirmationMACs(ka, aad []byte, suite ciphersuite.CipherSuite) ([]byte, []byte) {
	info := []byte("ConfirmationKeys")
	info = append(info, aad...)
	Kc := suite.DeriveKey(nil, ka, info)
	keyLength := len(Kc)
	return Kc[:keyLength/2], Kc[keyLength/2:]
}

func newClientSharedSecret(sharedSecret, keySecret, transcript, aad []byte, suite ciphersuite.CipherSuite) *ClientSharedSecret {
	return &ClientSharedSecret{suite, transcript, sharedSecret, keySecret, aad, nil, nil}
}

func newServerSharedSecret(sharedSecret, keySecret, transcript, aad []byte, suite ciphersuite.CipherSuite) *ServerSharedSecret {
	return &ServerSharedSecret{suite, transcript, sharedSecret, keySecret, aad, nil, nil}
}

// NewFromClientState gets a ClientSharedSecret from ClientState
func NewFromClientState(idA, idB, S, T, K, w, aad []byte, suite ciphersuite.CipherSuite) *ClientSharedSecret {
	// transcript = len(A) || A || len(B) || B || len(S) || S || len(T) || T || len(K)
	// || K || len(w) || w
	transcript := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(transcript, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(transcript, idB)
	}
	appendLenAndContent(transcript, S)
	appendLenAndContent(transcript, T)
	appendLenAndContent(transcript, K)
	appendLenAndContent(transcript, w)

	transcriptBytes := transcript.Bytes()
	transcriptHash := suite.HashDigest(transcriptBytes)
	blockSize := len(transcriptHash)

	Ke, Ka := transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]

	return newClientSharedSecret(Ke, Ka, transcriptBytes, aad, suite)
}

// NewFromServerState gets a ServerSharedSecret from ServerState
func NewFromServerState(idA, idB, S, T, K, w, aad []byte, suite ciphersuite.CipherSuite) *ServerSharedSecret {
	// transcript = len(A) || A || len(B) || B || len(S) || S || len(T) || T || len(K)
	// || K || len(w) || w
	transcript := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(transcript, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(transcript, idB)
	}
	appendLenAndContent(transcript, S)
	appendLenAndContent(transcript, T)
	appendLenAndContent(transcript, K)
	appendLenAndContent(transcript, w)

	transcriptBytes := transcript.Bytes()
	transcriptHash := suite.HashDigest(transcriptBytes)
	blockSize := len(transcriptHash)

	Ke, Ka := transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]

	return newServerSharedSecret(Ke, Ka, transcriptBytes, aad, suite)
}

// NewFromClientPlusState gets a ClientSharedSecret from ClientPlusState
func NewFromClientPlusState(idA, idB, X, Y, Z, V, w0, aad []byte, suite ciphersuite.CipherSuite) *ClientSharedSecret {
	// transcript = len(A) || A || len(B) || B || len(X) || X || len(Y) || Y || len(Z)
	// || Z || len(V) || V || len(w0) || w0
	transcript := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(transcript, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(transcript, idB)
	}
	appendLenAndContent(transcript, X)
	appendLenAndContent(transcript, Y)
	appendLenAndContent(transcript, Z)
	appendLenAndContent(transcript, V)
	appendLenAndContent(transcript, w0)

	transcriptBytes := transcript.Bytes()
	transcriptHash := suite.HashDigest(transcriptBytes)
	blockSize := len(transcriptHash)

	Ke, Ka := transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]

	return newClientSharedSecret(Ke, Ka, transcriptBytes, aad, suite)
}

// NewFromServerPlusState gets a ServerSharedSecret from ServerPlusState
func NewFromServerPlusState(idA, idB, X, Y, Z, V, w0, aad []byte, suite ciphersuite.CipherSuite) *ServerSharedSecret {
	// transcript = len(A) || A || len(B) || B || len(X) || X || len(Y) || Y || len(Z)
	// || Z || len(V) || V || len(w0) || w0
	transcript := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(transcript, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(transcript, idB)
	}
	appendLenAndContent(transcript, X)
	appendLenAndContent(transcript, Y)
	appendLenAndContent(transcript, Z)
	appendLenAndContent(transcript, V)
	appendLenAndContent(transcript, w0)

	transcriptBytes := transcript.Bytes()
	transcriptHash := suite.HashDigest(transcriptBytes)
	blockSize := len(transcriptHash)

	Ke, Ka := transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]

	return newServerSharedSecret(Ke, Ka, transcriptBytes, aad, suite)
}

func (s *ClientSharedSecret) generateConfirmations() {
	kcA, kcB := confirmationMACs(s.keySecret, s.aad, s.suite)
	s.confirmation = s.suite.Mac(s.transcript, kcA)
	s.remoteConfirmation = s.suite.Mac(s.transcript, kcB)
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s *ClientSharedSecret) GetConfirmation() []byte {
	if s.confirmation == nil {
		s.generateConfirmations()
	}
	return s.confirmation
}

// GetConfirmations gets both confirmation message (confirmation, remoteConfirmation) for possible state save.
func (s *ClientSharedSecret) GetConfirmations() ([]byte, []byte) {
	if s.confirmation == nil || s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	return s.confirmation, s.remoteConfirmation
}

// Verify verifies an incoming confirmation message.
func (s *ClientSharedSecret) Verify(incomingConfirmation []byte) error {
	if s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	if !s.suite.MacEqual(incomingConfirmation, s.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ClientSharedSecret) Bytes() []byte {
	return s.sharedSecret
}

func (s *ServerSharedSecret) generateConfirmations() {
	kcA, kcB := confirmationMACs(s.keySecret, s.aad, s.suite)
	s.confirmation = s.suite.Mac(s.transcript, kcB)
	s.remoteConfirmation = s.suite.Mac(s.transcript, kcA)
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s *ServerSharedSecret) GetConfirmation() []byte {
	if s.confirmation == nil {
		s.generateConfirmations()
	}
	return s.confirmation
}

// GetConfirmations gets both confirmation message (confirmation, remoteConfirmation) for possible state save.
func (s *ServerSharedSecret) GetConfirmations() ([]byte, []byte) {
	if s.confirmation == nil || s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	return s.confirmation, s.remoteConfirmation
}

// Verify verifies an incoming confirmation message.
func (s *ServerSharedSecret) Verify(incomingConfirmation []byte) error {
	if s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	if !s.suite.MacEqual(incomingConfirmation, s.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ServerSharedSecret) Bytes() []byte {
	return s.sharedSecret
}

// Confirmations provides a easy interface for confirmation verification, for state load.
type Confirmations struct {
	confirmation       []byte
	remoteConfirmation []byte
	suite              ciphersuite.CipherSuite
}

// NewConfirmations creates a Confirmations.
func NewConfirmations(confirmation, remoteConfirmation []byte, suite ciphersuite.CipherSuite) *Confirmations {
	return &Confirmations{confirmation, remoteConfirmation, suite}
}

// Bytes gets the confirmation message.
func (c Confirmations) Bytes() []byte {
	return c.confirmation
}

// Verify verifies an incoming confirmation message.
func (c Confirmations) Verify(incomingConfirmation []byte) error {
	if !c.suite.MacEqual(incomingConfirmation, c.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}
