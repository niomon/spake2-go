package ciphersuite

import (
// "math/big"

// kyber "go.dedis.ch/kyber/v3"
// "go.dedis.ch/kyber/v3/suites"
// "go.dedis.ch/kyber/v3/util/encoding"
)

// CipherSuite ...
type CipherSuite interface {
	Curve() Curve
	HashDigest([]byte) []byte
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	Mhf([]byte, []byte) ([]byte, error)
}

// Curve ... TODO
type Curve interface {
	M() Point
	N() Point
	P() Point
	RandomScalar() Scalar
	NewPoint([]byte) (Point, error)
	NewScalar([]byte) (Scalar, error)
}

// Point ... TODO
type Point interface {
	Bytes() []byte
	Add(Point) Point
	Neg() Point
	ScalarMul(Scalar) Point
	IsInfinity() bool
	IsSmallOrder() bool
}

// Scalar ... TODO
type Scalar interface {
	Bytes() []byte
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
}

// Hkdf is a struct of the options for HKDF.
type Hkdf struct {
	AAD []byte
}

// Scrypt is a struct of the options for scrypt.
type Scrypt struct {
	N, R, P int
}
