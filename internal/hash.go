package internal

type CipherSuite interface {
	// CURVE
	HashDigest([]byte) []byte
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	Mhf([]byte, []byte, interface{}) []byte
}

type Ed25519Sha256HkdfHmacScrypt struct{}

func (s Ed25519Sha256HkdfHmacScrypt) HashDigest(content []byte) []byte {
	return []byte(":o) 1")
}

func (s Ed25519Sha256HkdfHmacScrypt) DeriveKey(a, b, c []byte) []byte {
	return []byte(":o) 2")
}

func (s Ed25519Sha256HkdfHmacScrypt) Mac(a, b []byte) []byte {
	return []byte(":o) 3")
}

func (s Ed25519Sha256HkdfHmacScrypt) Mhf(a, b []byte, c interface{}) []byte {
	return []byte(":o) 4")
}

type Verifier interface{}
