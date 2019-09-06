package ciphersuite

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	kyber "go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/encoding"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Ed25519Sha256HkdfHmacScrypt is the ED25519-SHA256-HKDF-HMAC-SCRYPT cipher suite defined by the
// SPAKE2 speficiation [irtf-cfrg-spake2-08].
type Ed25519Sha256HkdfHmacScrypt struct {
	Scrypt *Scrypt
}

// Curve returns the Ed25519 curve.
func (s Ed25519Sha256HkdfHmacScrypt) Curve() Curve {
	return Ed25519{}
}

// HashDigest computes the hash digest for a content.
func (s Ed25519Sha256HkdfHmacScrypt) HashDigest(content []byte) []byte {
	hash := sha256.Sum256(content)
	return hash[:]
}

// HashSize returns the size of hashes.
func (s Ed25519Sha256HkdfHmacScrypt) HashSize() int {
	return 32
}

// DeriveKey derives a key from the salt, intermediate key material and info.
func (s Ed25519Sha256HkdfHmacScrypt) DeriveKey(salt, ikm, info []byte) []byte {
	hkdf := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key[:]
}

// Mac computes a key-hashed content.
func (s Ed25519Sha256HkdfHmacScrypt) Mac(content, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(content)
	hash := mac.Sum(nil)
	return hash[:]
}

// MacEqual checks two MACs are equal without leaking timing information
func (s Ed25519Sha256HkdfHmacScrypt) MacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// Mhf computes a derived password from password and salt.
func (s Ed25519Sha256HkdfHmacScrypt) Mhf(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, s.Scrypt.N, s.Scrypt.R, s.Scrypt.P, 32)
}

// Ed25519Point is a struct for the EDWARDS25519 curve. An implemention for the Point interface.
type Ed25519Point struct {
	v kyber.Point
}

// Bytes encodes an Ed25519Point to an array of bytes.
func (p Ed25519Point) Bytes() []byte {
	group := suites.MustFind("Ed25519")
	pStr, err := encoding.PointToStringHex(group, p.v)
	pBytes, err := hex.DecodeString(pStr)
	if err != nil {
		panic("cannot encode point")
	}
	return pBytes
}

// Add adds an Ed25519Point to return another Ed25519Point.
func (p Ed25519Point) Add(q Point) Point {
	qq, ok := q.(Ed25519Point)
	if !ok {
		panic("incorrect type of point")
	}
	group := suites.MustFind("Ed25519")
	r := group.Point().Add(p.v, qq.v)
	return Ed25519Point{v: r}
}

// Neg negates the Ed25519Point.
func (p Ed25519Point) Neg() Point {
	group := suites.MustFind("Ed25519")
	r := group.Point().Neg(p.v)
	return Ed25519Point{v: r}
}

// ScalarMul multiplies the point with a Ed25519Scalar.
func (p Ed25519Point) ScalarMul(t Scalar) Point {
	tt, ok := t.(Ed25519Scalar)
	if !ok {
		panic("incorrect type of scalar")
	}
	group := suites.MustFind("Ed25519")
	r := group.Point().Mul(tt.v, p.v)
	return Ed25519Point{v: r}
}

// IsInfinity checks if a point is the infinity point.
func (p Ed25519Point) IsInfinity() bool {
	group := suites.MustFind("Ed25519")
	point := group.Point().Set(p.v)
	null := group.Point().Null()
	return point.Equal(null)
}

// IsSmallOrder checks if a point is of small order.
func (p Ed25519Point) IsSmallOrder() bool {
	group := suites.MustFind("Ed25519")
	cofactor := Ed25519Scalar{v: group.Scalar().SetInt64(8)}
	return p.ScalarMul(cofactor).IsInfinity()
}

// Ed25519Scalar is a struct for the EDWARDS25519 scalar. An implementation for the Scalar interface.
type Ed25519Scalar struct {
	v kyber.Scalar
}

// Bytes encodes a Ed25519Scalar to an array of bytes.
func (s Ed25519Scalar) Bytes() []byte {
	sBytes, err := s.v.MarshalBinary()
	if err != nil {
		panic("cannot marshal scalar")
	}
	sBytes = reverse(sBytes)
	return sBytes
}

// Add adds an Ed25519Scalar to another.
func (s Ed25519Scalar) Add(t Scalar) Scalar {
	tt, ok := t.(Ed25519Scalar)
	if !ok {
		panic("incorrect type of scalar")
	}
	group := suites.MustFind("Ed25519")
	r := group.Scalar().Add(s.v, tt.v)
	return Ed25519Scalar{v: r}
}

// Mul multiplies an Ed25519Scalar to another.
func (s Ed25519Scalar) Mul(t Scalar) Scalar {
	tt, ok := t.(Ed25519Scalar)
	if !ok {
		panic("incorrect type of scalar")
	}
	group := suites.MustFind("Ed25519")
	r := group.Scalar().Mul(s.v, tt.v)
	return Ed25519Scalar{v: r}
}

// Neg negates the scalar.
func (s Ed25519Scalar) Neg() Scalar {
	group := suites.MustFind("Ed25519")
	r := group.Scalar().Neg(s.v)
	return Ed25519Scalar{v: r}
}

// Ed25519 is a struct for the Edwards25519 curve. An implemention for the Curve interface.
type Ed25519 struct{}

// M returns the specified point on the SPAKE2 [irtf-cfrg-spake2-08] for the protocol.
func (c Ed25519) M() Point {
	pointString, err := hex.DecodeString("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
	if err != nil {
		panic("invalid decode")
	}
	point, err := c.NewPoint(pointString)
	if err != nil {
		panic("invalid decode")
	}
	return point
}

// N returns the specified point on the SPAKE2 [irtf-cfrg-spake2-08] for the protocol.
func (c Ed25519) N() Point {
	pointString, err := hex.DecodeString("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
	if err != nil {
		panic("invalid decode")
	}
	point, err := c.NewPoint(pointString)
	if err != nil {
		panic("invalid decode")
	}
	return point
}

// P returns the base point on the Edwards25519 curve.
func (c Ed25519) P() Point {
	pointString, err := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	if err != nil {
		panic("invalid decode")
	}
	point, err := c.NewPoint(pointString)
	if err != nil {
		panic("invalid decode")
	}
	return point
}

// RandomScalar returns a random Ed25519Scalar.
func (c Ed25519) RandomScalar() Scalar {
	p := make([]byte, 72)
	_, err := rand.Read(p)
	if err != nil {
		panic("cannot generate random scalar")
	}
	pScalar, err := c.NewScalar(p)
	if err != nil {
		panic("cannot generate random scalar")
	}
	return pScalar
}

// NewPoint decodes an array of bytes to an Ed25519Point.
func (c Ed25519) NewPoint(p []byte) (Point, error) {
	group := suites.MustFind("Ed25519")
	pStr := hex.EncodeToString(p)
	pKyberPt, err := encoding.StringHexToPoint(group, pStr)
	if err != nil {
		return nil, err
	}
	return Ed25519Point{v: pKyberPt}, nil
}

// NewScalar decodes an array of bytes to an Ed25519Scalar.
func (c Ed25519) NewScalar(p []byte) (Scalar, error) {
	p = reverse(p)
	group := suites.MustFind("Ed25519")
	pStr := hex.EncodeToString(p)
	pKyberSc, err := encoding.StringHexToScalar(group, pStr)
	if err != nil {
		return nil, err
	}
	return Ed25519Scalar{v: pKyberSc}, nil
}

// ScalarSize returns the size of scalars.
func (c Ed25519) ScalarSize() int {
	return 32
}

// PointSize returns the size of points.
func (c Ed25519) PointSize() int {
	return 32
}

func reverse(p []byte) []byte {
	q := make([]byte, len(p))
	for i := 0; 2*i < len(p); i++ {
		j := len(p) - 1 - i
		q[i], q[j] = p[j], p[i]
	}
	return q[:]
}
