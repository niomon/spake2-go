package spake2go

import (
	"bytes"
	"errors"

	"authcore.io/spake2go/internal/ciphersuite"
)

func confirmationMACs(ka, aad []byte, suite ciphersuite.CipherSuite) ([]byte, []byte) {
	info := []byte("ConfirmationKeys")
	info = append(info, aad...)
	Kc := suite.DeriveKey(nil, ka, info)
	keyLength := len(Kc)
	return Kc[:keyLength/2], Kc[keyLength/2:]
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

	KcA, KcB := confirmationMACs(Ka, aad, suite)

	return &ClientSharedSecret{suite, transcriptBytes, Ke, KcA, KcB}
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

	KcA, KcB := confirmationMACs(Ka, aad, suite)

	return &ServerSharedSecret{suite, transcriptBytes, Ke, KcA, KcB}
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

	KcA, KcB := confirmationMACs(Ka, aad, suite)

	return &ClientSharedSecret{suite, transcriptBytes, Ke, KcA, KcB}
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

	KcA, KcB := confirmationMACs(Ka, aad, suite)

	return &ServerSharedSecret{suite, transcriptBytes, Ke, KcA, KcB}
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s ClientSharedSecret) GetConfirmation() []byte {
	return s.suite.Mac(s.kcA, s.transcript)
}

// Verify verifies an incoming confirmation message.
func (s ClientSharedSecret) Verify(incomingConfirmation []byte) error {
	if !s.suite.MacEqual(incomingConfirmation, s.suite.Mac(s.kcB, s.transcript)) {
		return errors.New("Verification Failed")
	}
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ClientSharedSecret) Bytes() []byte {
	return s.sharedSecret
}

// GetConfirmation gets a confirmation message for the key confirmation.
func (s ServerSharedSecret) GetConfirmation() []byte {
	return s.suite.Mac(s.kcB, s.transcript)
}

// Verify verifies an incoming confirmation message.
func (s ServerSharedSecret) Verify(incomingConfirmation []byte) error {
	if !s.suite.MacEqual(incomingConfirmation, s.suite.Mac(s.kcA, s.transcript)) {
		return errors.New("Verification Failed")
	}
	return nil
}

// Bytes gets the shared secret derived from the protocol.
func (s ServerSharedSecret) Bytes() []byte {
	return s.sharedSecret
}

// func (s ServerSharedSecret) SetBytes(b []bytes) bool {}
