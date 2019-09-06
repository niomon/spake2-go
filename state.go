package spake2

import (
	"errors"
)

// Finish verifies an incomingMessage from the server and returns a shared secret if it is
// validated.
func (s ClientState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	incomingElement, err := s.suite.Curve().NewPoint(incomingMessage)
	if err != nil {
		return nil, err
	}

	if incomingElement.IsSmallOrder() {
		return nil, errors.New("Corrupt Message")
	}

	verifierScalar, err := s.suite.Curve().NewScalar(s.verifier)
	if err != nil {
		return nil, err
	}

	//  K = (S+N*(-w))*x
	tmp := incomingElement.Add(s.suite.Curve().N().ScalarMul(verifierScalar.Neg()))
	keyElement := tmp.ScalarMul(s.x)
	keyBytes := keyElement.Bytes()
	return NewFromClientState(s.clientIdentity, s.serverIdentity, incomingMessage, s.msgT, keyBytes, s.verifier, s.aad, s.suite), nil
}

// Finish verifies an incomingMessage from the client and returns a shared secret if it is
// validated.
func (s ServerState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	incomingElement, err := s.suite.Curve().NewPoint(incomingMessage)
	if err != nil {
		return nil, err
	}

	if incomingElement.IsSmallOrder() {
		return nil, errors.New("Corrupt Message")
	}

	verifierScalar, err := s.suite.Curve().NewScalar(s.verifier)
	if err != nil {
		return nil, err
	}

	//  K = y*(T-w*M)
	tmp := incomingElement.Add(s.suite.Curve().M().ScalarMul(verifierScalar.Neg()))
	keyElement := tmp.ScalarMul(s.y)
	keyBytes := keyElement.Bytes()

	return NewFromServerState(s.clientIdentity, s.serverIdentity, s.msgS, incomingMessage, keyBytes, s.verifier, s.aad, s.suite), nil
}

// Finish verifies an incomingMessage from the server and returns a shared secret if it is
// validated.
func (s ClientPlusState) Finish(incomingMessage []byte) (*ClientSharedSecret, error) {
	incomingElement, err := s.suite.Curve().NewPoint(incomingMessage)
	if err != nil {
		return nil, err
	}

	if incomingElement.IsSmallOrder() {
		return nil, errors.New("Corrupt Message")
	}

	w0Scalar, err := s.suite.Curve().NewScalar(padScalarBytes(s.verifierW0, s.suite.Curve().ScalarSize()))
	if err != nil {
		return nil, err
	}

	w1Scalar, err := s.suite.Curve().NewScalar(padScalarBytes(s.verifierW1, s.suite.Curve().ScalarSize()))
	if err != nil {
		return nil, err
	}

	// Z = (Y+N*(-w0))*x, V = (Y+N*(-w0))*w1
	tmp := incomingElement.Add(s.suite.Curve().N().ScalarMul(w0Scalar.Neg()))
	ZElement := tmp.ScalarMul(s.x)
	ZBytes := ZElement.Bytes()
	VElement := tmp.ScalarMul(w1Scalar)
	VBytes := VElement.Bytes()

	return NewFromClientPlusState(s.clientIdentity, s.serverIdentity, s.msgX, incomingMessage, ZBytes, VBytes, s.verifierW0, s.aad, s.suite), nil
}

// Finish verifies an incomingMessage from the client and returns a shared secret if it is
// validated.
func (s ServerPlusState) Finish(incomingMessage []byte) (*ServerSharedSecret, error) {
	incomingElement, err := s.suite.Curve().NewPoint(incomingMessage)
	if err != nil {
		return nil, err
	}

	if incomingElement.IsSmallOrder() {
		return nil, errors.New("Corrupt Message")
	}

	w0Scalar, err := s.suite.Curve().NewScalar(padScalarBytes(s.verifierW0, s.suite.Curve().ScalarSize()))
	if err != nil {
		return nil, err
	}

	LElement, err := s.suite.Curve().NewPoint(s.verifierL)
	if err != nil {
		return nil, err
	}

	// Z = (X+M*(-w0))*y, V = y*L
	tmp := incomingElement.Add(s.suite.Curve().M().ScalarMul(w0Scalar.Neg()))
	ZElement := tmp.ScalarMul(s.y)
	ZBytes := ZElement.Bytes()
	VElement := LElement.ScalarMul(s.y)
	VBytes := VElement.Bytes()

	return NewFromServerPlusState(s.clientIdentity, s.serverIdentity, incomingMessage, s.msgY, ZBytes, VBytes, s.verifierW0, s.aad, s.suite), nil
}
