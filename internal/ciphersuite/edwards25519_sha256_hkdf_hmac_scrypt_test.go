package ciphersuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConversion(t *testing.T) {
	suite := Ed25519Sha256HkdfHmacScrypt{&Scrypt{16, 1, 1}}
	point := suite.Curve().M()
	pointAfterConv, err := suite.Curve().NewPoint(point.Bytes())
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, point, pointAfterConv)

	scalar := suite.Curve().RandomScalar()
	scalarAfterConv, err := suite.Curve().NewScalar(scalar.Bytes())
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, scalar.Bytes(), scalarAfterConv.Bytes())
}

func TestNeg(t *testing.T) {
	suite := Ed25519Sha256HkdfHmacScrypt{&Scrypt{16, 1, 1}}
	scalar := suite.Curve().RandomScalar()
	scalarNeg := scalar.Neg()
	assert.Equal(t, scalar.Bytes(), scalarNeg.Neg().Bytes())
}
