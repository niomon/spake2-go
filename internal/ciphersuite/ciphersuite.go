package ciphersuite

// CipherSuite ...
type CipherSuite interface {
	// CURVE
	HashDigest([]byte) []byte
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	Mhf([]byte, []byte, interface{}) []byte
}

// Ed25519Sha256HkdfHmacScrypt ...
type Ed25519Sha256HkdfHmacScrypt struct{}

// HashDigest ...
func (s Ed25519Sha256HkdfHmacScrypt) HashDigest(content []byte) []byte {
	return []byte(":o) 1")
}

// DeriveKey ...
func (s Ed25519Sha256HkdfHmacScrypt) DeriveKey(a, b, c []byte) []byte {
	return []byte(":o) 2")
}

// Mac ...
func (s Ed25519Sha256HkdfHmacScrypt) Mac(a, b []byte) []byte {
	return []byte(":o) 3")
}

// Mhf ...
func (s Ed25519Sha256HkdfHmacScrypt) Mhf(a, b []byte, c interface{}) []byte {
	return []byte(":o) 4")
}

// Verifier ...
type Verifier interface{}
