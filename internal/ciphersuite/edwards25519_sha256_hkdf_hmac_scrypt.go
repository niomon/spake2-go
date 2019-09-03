package ciphersuite

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"

	kyber "go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/hkdf"
	// "go.dedis.ch/kyber/v3/group/edwards25519"
	"golang.org/x/crypto/scrypt"
)

// Ed25519Sha256HkdfHmacScrypt is the ED25519-SHA256-HKDF-HMAC-SCRYPT cipher suite defined by the
// SPAKE2 speficiation [irtf-cfrg-spake2-08].
type Ed25519Sha256HkdfHmacScrypt struct {
	Scrypt *Scrypt
	Hkdf   *Hkdf
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
	return []byte{}
}

// Add adds an Ed25519Point to return another Ed25519Point.
func (p Ed25519Point) Add(q Point) Point {
	return p // TODO
}

// Neg negates the Ed25519Point.
func (p Ed25519Point) Neg() Point {
	return p // TODO
}

// ScalarMul multiplies the point with a Ed25519Scalar.
func (p Ed25519Point) ScalarMul(t Scalar) Point {
	return p
}

// IsInfinity checks if a point is the infinity point.
func (p Ed25519Point) IsInfinity() bool {
	return false // TODO
}

// IsSmallOrder checks if a point is of small order.
func (p Ed25519Point) IsSmallOrder() bool {
	return p.ScalarMul(Ed25519Scalar{v: big.NewInt(8)}).IsInfinity()
}

// Ed25519Scalar is a struct for the EDWARDS25519 scalar. An implementation for the Scalar interface.
type Ed25519Scalar struct {
	v *big.Int
}

// Bytes encodes a Ed25519Scalar to an array of bytes.
func (s Ed25519Scalar) Bytes() []byte {
	return s.v.Bytes()
}

// Add adds an Ed25519Scalar to another.
func (s Ed25519Scalar) Add(t Scalar) Scalar {
	tt, ok := t.(Ed25519Scalar)
	if !ok {
		panic("incorrect type of scalar")
	}
	u := new(big.Int)
	u.Add(s.v, tt.v)
	return NewEd25519Scalar(u)
}

// Mul multiplies an Ed25519Scalar to another.
func (s Ed25519Scalar) Mul(t Scalar) Scalar {
	tt, ok := t.(Ed25519Scalar)
	if !ok {
		panic("incorrect type of scalar")
	}
	u := new(big.Int)
	u.Mul(s.v, tt.v)
	return NewEd25519Scalar(u)
}

// NewEd25519Scalar returns a Ed25519Scalar by a big.Int.
func NewEd25519Scalar(v *big.Int) Ed25519Scalar {
	order := new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	v.Mod(v, order)
	return Ed25519Scalar{v}
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
	// curve := edwards25519.Curve{}
	// curve.
	return Ed25519Point{}, nil
}

// NewScalar decodes an array of bytes to an Ed25519Scalar.
func (c Ed25519) NewScalar(p []byte) (Scalar, error) {
	pInt := new(big.Int)
	pInt.SetBytes(p)
	return NewEd25519Scalar(pInt), nil
}

func (c Ed25519) cofactor() *big.Int {
	return big.NewInt(8)
}
