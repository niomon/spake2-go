package ciphersuite

// CipherSuite is an interface for a SPAKE2 (or SPAKE2) cipher suite.
type CipherSuite interface {
	Curve() Curve
	HashDigest([]byte) []byte
	HashSize() int
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	MacEqual([]byte, []byte) bool
	Mhf([]byte, []byte) ([]byte, error)
}

// Curve is an interface for the elliptic curve.
type Curve interface {
	M() Point
	N() Point
	P() Point
	RandomScalar() Scalar
	NewPoint([]byte) (Point, error)
	NewScalar([]byte) (Scalar, error)
	ScalarSize() int
	PointSize() int
}

// Point is an interface for a point on the elliptic curve.
type Point interface {
	Bytes() []byte
	Add(Point) Point
	Neg() Point
	ScalarMul(Scalar) Point
	IsInfinity() bool
	IsSmallOrder() bool
}

// Scalar is an interface for a scalar on the elliptic curve.
type Scalar interface {
	Bytes() []byte
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
	Neg() Scalar
}

// Scrypt is a struct of the options for scrypt.
type Scrypt struct {
	N, R, P int
}
