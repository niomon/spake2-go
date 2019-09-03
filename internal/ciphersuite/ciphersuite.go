package ciphersuite

// CipherSuite ...
type CipherSuite interface {
	// CURVE
	HashDigest([]byte) []byte
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	Mhf([]byte, []byte, interface{}) []byte
}

// Hkdf is a struct of the options for HKDF.
type Hkdf struct {
	AAD []byte
}

// Scrypt is a struct of the options for scrypt.
type Scrypt struct {
	N, R, P uint
}

// Ed25519Sha256HkdfHmacScrypt is the ED25519-SHA256-HKDF-HMAC-SCRYPT cipher suite defined by the
// SPAKE2 speficiation [irtf-cfrg-spake2-08].
type Ed25519Sha256HkdfHmacScrypt struct {
	Scrypt *Scrypt
	Hkdf   *Hkdf
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

// Mhf computes a derived password from passphrase and salt.
func (s Ed25519Sha256HkdfHmacScrypt) Mhf(passphrase, salt []byte, options interface{}) []byte {
	return []byte(":o) 4")
}
