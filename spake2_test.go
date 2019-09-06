package spake2

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

type MHFOptions struct {
	N    int    `yaml:"n"`
	R    int    `yaml:"r"`
	P    int    `yaml:"p"`
	Salt string `yaml:"salt"`
}

type KDFOptions struct {
	AAD string `yaml:"AAD"`
}

type SPAKE2TestVector struct {
	MHF            MHFOptions `yaml:"mhf"`
	KDF            KDFOptions `yaml:"kdf"`
	ClientIdentity string     `yaml:"client_identity"`
	ServerIdentity string     `yaml:"server_identity"`
	Password       string     `yaml:"password"`
	X              string     `yaml:"x"`
	Y              string     `yaml:"y"`
	Verifier       string     `yaml:"verifier"`
	MessageA       string     `yaml:"message_a"`
	MessageB       string     `yaml:"message_b"`
	Transcript     string     `yaml:"transcript"`
	HashTranscript string     `yaml:"hash_transcript"`
	ConfirmationA  string     `yaml:"confirmation_a"`
	ConfirmationB  string     `yaml:"confirmation_b"`
	SharedSecret   string     `yaml:"shared_secret"`
}

type SPAKE2PlusTestVector struct {
	MHF            MHFOptions `yaml:"mhf"`
	KDF            KDFOptions `yaml:"kdf"`
	ClientIdentity string     `yaml:"client_identity"`
	ServerIdentity string     `yaml:"server_identity"`
	Password       string     `yaml:"password"`
	X              string     `yaml:"x"`
	Y              string     `yaml:"y"`
	VerifierW0     string     `yaml:"verifier_w0"`
	VerifierL      string     `yaml:"verifier_l"`
	MessageA       string     `yaml:"message_a"`
	MessageB       string     `yaml:"message_b"`
	Transcript     string     `yaml:"transcript"`
	HashTranscript string     `yaml:"hash_transcript"`
	ConfirmationA  string     `yaml:"confirmation_a"`
	ConfirmationB  string     `yaml:"confirmation_b"`
	SharedSecret   string     `yaml:"shared_secret"`
}

// SPAKE2

func TestSPAKE2(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte("")
	expectedVerifier, err := hex.DecodeString("0ec6b7483ed26e08802b41f4032086a017d0fbc866e3af79bf38eff06efd0bb2")
	if !assert.NoError(t, err) {
		return
	}

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}

	verifier, err := s.ComputeVerifier(password, salt)
	if !assert.Equal(t, expectedVerifier, verifier) {
		return
	}

	// Creates a SPAKE2 client and a SPAKE2 server.
	one, err := suite.Curve().NewScalar([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if !assert.NoError(t, err) {
		return
	}
	stateA, messageA, err := s.startClient(clientIdentity, serverIdentity, password, salt, aad, one)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.startServer(clientIdentity, serverIdentity, verifier, aad, one)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA := sharedSecretA.GetConfirmation()
	confirmationB := sharedSecretB.GetConfirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())

	// Test not plugged x,y
	// Creates a SPAKE2 instance
	s, err = NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}

	verifier, err = s.ComputeVerifier(password, salt)
	if !assert.Equal(t, expectedVerifier, verifier) {
		return
	}

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err = s.StartClient(clientIdentity, serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err = s.StartServer(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err = stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err = stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA = sharedSecretA.GetConfirmation()
	confirmationB = sharedSecretB.GetConfirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())

}

func TestSPAKE2WithWrongPassword(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte("")

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, []byte("a_wrong_password"), salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.GetConfirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func TestSPAKE2WithWrongClientIdentity(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte("")
	// Creates a SPAKE2 instance
	s, err := NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient([]byte("another_client"), serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.GetConfirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func TestSPAKE2WithWrongServerIdentity(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte{}

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, []byte("another_server"), verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A verifies the confirmation message from B - and fails.
	confirmationB := sharedSecretB.GetConfirmation()
	err = sharedSecretA.Verify(confirmationB)
	assert.Error(t, err)
}

func TestSPAKE2Vectors(t *testing.T) {
	yamlFile, err := ioutil.ReadFile("./test_vectors/spake2_ed25519_sha256_hkdf_hmac_scrypt.yml")
	assert.NoError(t, err)

	var testVectors []SPAKE2TestVector
	err = yaml.Unmarshal([]byte(yamlFile), &testVectors)
	assert.NoError(t, err)

	for _, testVector := range testVectors {
		// Defines the cipher suite
		suite := Ed25519Sha256HkdfHmacScrypt(
			Scrypt(testVector.MHF.N, testVector.MHF.R, testVector.MHF.P),
		)

		clientIdentity := []byte(testVector.ClientIdentity)
		serverIdentity := []byte(testVector.ServerIdentity)
		password := []byte(testVector.Password)
		salt := []byte(testVector.MHF.Salt)
		aad := []byte(testVector.KDF.AAD)

		xHex, err := hex.DecodeString(testVector.X)
		if !assert.NoError(t, err) {
			return
		}
		x, err := suite.Curve().NewScalar(padScalarBytes(xHex, suite.Curve().ScalarSize()))
		if !assert.NoError(t, err) {
			return
		}
		yHex, err := hex.DecodeString(testVector.Y)
		if !assert.NoError(t, err) {
			return
		}
		y, err := suite.Curve().NewScalar(padScalarBytes(yHex, suite.Curve().ScalarSize()))
		if !assert.NoError(t, err) {
			return
		}
		expectedVerifier, err := hex.DecodeString(testVector.Verifier)
		if !assert.NoError(t, err) {
			return
		}
		expectedMessageA, err := hex.DecodeString(testVector.MessageA)
		if !assert.NoError(t, err) {
			return
		}
		expectedMessageB, err := hex.DecodeString(testVector.MessageB)
		if !assert.NoError(t, err) {
			return
		}
		// expectedTranscript, err := hex.DecodeString(testVector.Transcript)
		// if !assert.NoError(t, err) {
		// 	return
		// }
		// expectedHashTranscript, err := hex.DecodeString(testVector.HashTranscript)
		// if !assert.NoError(t, err) {
		// 	return
		// }
		expectedConfirmationA, err := hex.DecodeString(testVector.ConfirmationA)
		if !assert.NoError(t, err) {
			return
		}
		expectedConfirmationB, err := hex.DecodeString(testVector.ConfirmationB)
		if !assert.NoError(t, err) {
			return
		}
		expectedSharedSecret, err := hex.DecodeString(testVector.SharedSecret)
		if !assert.NoError(t, err) {
			return
		}

		// Creates a SPAKE2 instance
		s, err := NewSPAKE2(suite)
		if !assert.NoError(t, err) {
			return
		}

		verifier, err := s.ComputeVerifier(password, salt)
		if !assert.Equal(t, expectedVerifier, verifier) {
			return
		}

		// Creates a SPAKE2 client and a SPAKE2 server.
		stateA, messageA, err := s.startClient(clientIdentity, serverIdentity, password, salt, aad, x)
		if !assert.NoError(t, err) || !assert.Equal(t, expectedMessageA, messageA) {
			return
		}
		stateB, messageB, err := s.startServer(clientIdentity, serverIdentity, verifier, aad, y)
		if !assert.NoError(t, err) || !assert.Equal(t, expectedMessageB, messageB) {
			return
		}

		// A and B verify the incoming message from each other.
		sharedSecretA, err := stateA.Finish(messageB)
		if !assert.NoError(t, err) {
			return
		}
		sharedSecretB, err := stateB.Finish(messageA)
		if !assert.NoError(t, err) {
			return
		}

		// A and B verify the confirmation message from each other.
		confirmationA := sharedSecretA.GetConfirmation()
		confirmationB := sharedSecretB.GetConfirmation()
		if !assert.Equal(t, expectedConfirmationA, confirmationA) || !assert.Equal(t, expectedConfirmationB, confirmationB) {
			return
		}

		err = sharedSecretA.Verify(confirmationB)
		if !assert.NoError(t, err) {
			return
		}
		err = sharedSecretB.Verify(confirmationA)
		if !assert.NoError(t, err) {
			return
		}

		// A and B have a common shared secret.
		assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
		assert.Equal(t, expectedSharedSecret, sharedSecretA.Bytes())
	}
}

// SPAKE2+

func TestSPAKE2Plus(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte("")
	expectedVerifierW0, err := hex.DecodeString("7329b4dddcffdf5d3942a223ee58fa39")
	if !assert.NoError(t, err) {
		return
	}
	expectedVerifierL, err := hex.DecodeString("3f3ecdc0aa6298b17b9bfaf4c4c047400a21f0ccfd8c223bf2f2a883edfc6ac5")
	if !assert.NoError(t, err) {
		return
	}

	// Creates a SPAKE2+ instance
	s, err := NewSPAKE2Plus(suite)
	if !assert.NoError(t, err) {
		return
	}

	verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)
	if !assert.Equal(t, expectedVerifierW0, verifierW0) {
		return
	}
	if !assert.Equal(t, expectedVerifierL, verifierL) {
		return
	}

	one, _ := suite.Curve().NewScalar([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.startClient(clientIdentity, serverIdentity, password, salt, aad, one)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.startServer(clientIdentity, serverIdentity, verifierW0, verifierL, aad, one)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA := sharedSecretA.GetConfirmation()
	confirmationB := sharedSecretB.GetConfirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
}

func TestSPAKE2PlusWithWrongPassword(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte{}

	// Creates a SPAKE2+ instance
	s, err := NewSPAKE2Plus(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)

	// Creates a SPAKE2+ client and a SPAKE2+ server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, []byte("a_wrong_password"), salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifierW0, verifierL, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.GetConfirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func TestSPAKE2PlusWithWrongClientIdentity(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte{}

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2Plus(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient([]byte("another_client"), serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, serverIdentity, verifierW0, verifierL, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.GetConfirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func TestSPAKE2PlusWithWrongServerIdentity(t *testing.T) {
	// Defines the cipher suite
	suite := Ed25519Sha256HkdfHmacScrypt(Scrypt(16, 1, 1))

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")
	aad := []byte{}

	// Creates a SPAKE2 instance
	s, err := NewSPAKE2Plus(suite)
	if !assert.NoError(t, err) {
		return
	}
	verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartClient(clientIdentity, serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartServer(clientIdentity, []byte("another_server"), verifierW0, verifierL, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A verifies the confirmation message from B - and fails.
	confirmationB := sharedSecretB.GetConfirmation()
	err = sharedSecretA.Verify(confirmationB)
	assert.Error(t, err)
}

func TestSPAKE2PlusVectors(t *testing.T) {
	yamlFile, err := ioutil.ReadFile("./test_vectors/spake2plus_ed25519_sha256_hkdf_hmac_scrypt.yml")
	assert.NoError(t, err)

	var testVectors []SPAKE2PlusTestVector
	err = yaml.Unmarshal([]byte(yamlFile), &testVectors)
	assert.NoError(t, err)

	for _, testVector := range testVectors {
		// Defines the cipher suite
		suite := Ed25519Sha256HkdfHmacScrypt(
			Scrypt(testVector.MHF.N, testVector.MHF.R, testVector.MHF.P),
		)

		clientIdentity := []byte(testVector.ClientIdentity)
		serverIdentity := []byte(testVector.ServerIdentity)
		password := []byte(testVector.Password)
		salt := []byte(testVector.MHF.Salt)
		aad := []byte(testVector.KDF.AAD)

		xHex, err := hex.DecodeString(testVector.X)
		if !assert.NoError(t, err) {
			return
		}
		x, err := suite.Curve().NewScalar(xHex)
		if !assert.NoError(t, err) {
			return
		}
		yHex, err := hex.DecodeString(testVector.Y)
		if !assert.NoError(t, err) {
			return
		}
		y, err := suite.Curve().NewScalar(yHex)
		if !assert.NoError(t, err) {
			return
		}
		expectedVerifierW0, err := hex.DecodeString(testVector.VerifierW0)
		if !assert.NoError(t, err) {
			return
		}
		expectedVerifierL, err := hex.DecodeString(testVector.VerifierL)
		if !assert.NoError(t, err) {
			return
		}
		expectedMessageA, err := hex.DecodeString(testVector.MessageA)
		if !assert.NoError(t, err) {
			return
		}
		expectedMessageB, err := hex.DecodeString(testVector.MessageB)
		if !assert.NoError(t, err) {
			return
		}
		// expectedTranscript, err := hex.DecodeString(testVector.Transcript)
		// if !assert.NoError(t, err) {
		// 	return
		// }
		// expectedHashTranscript, err := hex.DecodeString(testVector.HashTranscript)
		// if !assert.NoError(t, err) {
		// 	return
		// }
		expectedConfirmationA, err := hex.DecodeString(testVector.ConfirmationA)
		if !assert.NoError(t, err) {
			return
		}
		expectedConfirmationB, err := hex.DecodeString(testVector.ConfirmationB)
		if !assert.NoError(t, err) {
			return
		}
		expectedSharedSecret, err := hex.DecodeString(testVector.SharedSecret)
		if !assert.NoError(t, err) {
			return
		}

		// Creates a SPAKE2+ instance
		s, err := NewSPAKE2Plus(suite)
		if !assert.NoError(t, err) {
			return
		}

		verifierW0, verifierL, err := s.ComputeVerifier(password, salt, clientIdentity, serverIdentity)
		if !assert.Equal(t, expectedVerifierW0, verifierW0) {
			return
		}
		if !assert.Equal(t, expectedVerifierL, verifierL) {
			return
		}

		// Creates a SPAKE2+ client and a SPAKE2+ server.
		stateA, messageA, err := s.startClient(clientIdentity, serverIdentity, password, salt, aad, x)
		if !assert.NoError(t, err) || !assert.Equal(t, expectedMessageA, messageA) {
			return
		}
		stateB, messageB, err := s.startServer(clientIdentity, serverIdentity, verifierW0, verifierL, aad, y)
		if !assert.NoError(t, err) || !assert.Equal(t, expectedMessageB, messageB) {
			return
		}

		// A and B verify the incoming message from each other.
		sharedSecretA, err := stateA.Finish(messageB)
		if !assert.NoError(t, err) {
			return
		}
		sharedSecretB, err := stateB.Finish(messageA)
		if !assert.NoError(t, err) {
			return
		}

		// A and B verify the confirmation message from each other.
		confirmationA := sharedSecretA.GetConfirmation()
		confirmationB := sharedSecretB.GetConfirmation()
		if !assert.Equal(t, expectedConfirmationA, confirmationA) || !assert.Equal(t, expectedConfirmationB, confirmationB) {
			return
		}

		err = sharedSecretA.Verify(confirmationB)
		if !assert.NoError(t, err) {
			return
		}
		err = sharedSecretB.Verify(confirmationA)
		if !assert.NoError(t, err) {
			return
		}

		// A and B have a common shared secret.
		assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
		assert.Equal(t, expectedSharedSecret, sharedSecretA.Bytes())
	}
}
