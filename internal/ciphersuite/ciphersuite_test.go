package ciphersuite

// import (
// 	"testing"
// )

<<<<<<< HEAD
// func TestD(t *testing.T) {}
=======
func TestD(t *testing.T) {
	s := Ed25519Sha256HkdfHmacScrypt{}
	h := s.HashDigest([]byte(":o)"))
	k := s.DeriveKey([]byte(":o)"), []byte(":o)"), []byte(":o)"))
	m := s.Mac([]byte(":o)"), []byte(":o)"))
	f, _ := s.Mhf([]byte(":o)"), []byte(":o)"))
	t.Log(h, k, m, f)
}
>>>>>>> Implement SharedSecret and State.
