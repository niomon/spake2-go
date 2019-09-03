package ciphersuite

import (
	// "math/big"

	// kyber "go.dedis.ch/kyber/v3"
	// "go.dedis.ch/kyber/v3/suites"
	// "go.dedis.ch/kyber/v3/util/encoding"
	"golang.org/x/crypto/scrypt"
)

// CipherSuite ...
type CipherSuite interface {
	Curve() *Curve
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
	Order() Scalar
	Cofactor() Scalar
	RandomScalar() Scalar
	NewPoint([]byte) Point
	NewScalar([]byte) Scalar
}

// Point ... TODO
type Point interface {
	Bytes() []byte
	Add(Point) Point
	Neg() Point
	IsInfinity() bool
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

// Ed25519Sha256HkdfHmacScrypt is the ED25519-SHA256-HKDF-HMAC-SCRYPT cipher suite defined by the
// SPAKE2 speficiation [irtf-cfrg-spake2-08].
type Ed25519Sha256HkdfHmacScrypt struct {
	Scrypt *Scrypt
	Hkdf   *Hkdf
}

// Curve ... TODO
func (s Ed25519Sha256HkdfHmacScrypt) Curve() *Curve {
	return nil
}

// HashDigest computes the hash digest for a content.
func (s Ed25519Sha256HkdfHmacScrypt) HashDigest(content []byte) []byte {
	return []byte(":o) 1")
}

// DeriveKey derives a key from the salt, intermediate key material and info.
func (s Ed25519Sha256HkdfHmacScrypt) DeriveKey(salt, ikm, info []byte) []byte {
	return []byte(":o) 2")
}

// Mac computes a key-hashed content.
func (s Ed25519Sha256HkdfHmacScrypt) Mac(content, secret []byte) []byte {
	return []byte(":o) 3")
}

// Mhf computes a derived password from password and salt.
func (s Ed25519Sha256HkdfHmacScrypt) Mhf(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, s.Scrypt.N, s.Scrypt.R, s.Scrypt.P, 32)
}
