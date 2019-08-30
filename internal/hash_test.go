package internal

import (
	"testing"
)

func TestD(t *testing.T) {
	s := Ed25519Sha256HkdfHmacScrypt{}
	h := s.HashDigest([]byte(":o)"))
	k := s.DeriveKey([]byte(":o)"), []byte(":o)"), []byte(":o)"))
	m := s.Mac([]byte(":o)"), []byte(":o)"))
	f := s.Mhf([]byte(":o)"), []byte(":o)"), "1337")
	t.Log(h, k, m, f)
}
