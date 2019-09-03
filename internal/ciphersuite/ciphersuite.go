package ciphersuite

<<<<<<< HEAD
// CipherSuite is an interface for a SPAKE2 (or SPAKE2) cipher suite.
=======
// "math/big"

// kyber "go.dedis.ch/kyber/v3"
// "go.dedis.ch/kyber/v3/suites"
// "go.dedis.ch/kyber/v3/util/encoding"

// CipherSuite ...
>>>>>>> Implement SharedSecret and State.
type CipherSuite interface {
	Curve() Curve
	HashDigest([]byte) []byte
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	Mhf([]byte, []byte) ([]byte, error)
}

<<<<<<< HEAD
// Curve is an interface for the elliptic curve.
=======
// Curve ... TODO
>>>>>>> Implement SharedSecret and State.
type Curve interface {
	M() Point
	N() Point
	P() Point
	RandomScalar() Scalar
	NewPoint([]byte) (Point, error)
	NewScalar([]byte) (Scalar, error)
}

<<<<<<< HEAD
// Point is an interface for a point on the elliptic curve.
=======
// Point ... TODO
>>>>>>> Implement SharedSecret and State.
type Point interface {
	Bytes() []byte
	Add(Point) Point
	Neg() Point
	ScalarMul(Scalar) Point
	IsInfinity() bool
	IsSmallOrder() bool
}

<<<<<<< HEAD
// Scalar is an interface for a scalar on the elliptic curve.
=======
// Scalar ... TODO
>>>>>>> Implement SharedSecret and State.
type Scalar interface {
	Bytes() []byte
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
	Neg() Scalar
}

// Hkdf is a struct of the options for HKDF.
type Hkdf struct {
	AAD []byte
}

// Scrypt is a struct of the options for scrypt.
type Scrypt struct {
	N, R, P int
}
