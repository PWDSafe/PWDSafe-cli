package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func aesGCMSeal(t *testing.T, key, nonce, plaintext []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	return gcm.Seal(nil, nonce, plaintext, nil)
}

func TestDecryptPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshaling PKCS8: %v", err)
	}

	vaultKey := make([]byte, 32)
	if _, err := rand.Read(vaultKey); err != nil {
		t.Fatalf("generating vault key: %v", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext := aesGCMSeal(t, vaultKey, nonce, der)
	encryptedPrivKey := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))

	got, err := DecryptPrivateKey(encryptedPrivKey, vaultKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if !got.Equal(rsaKey) {
		t.Fatal("decrypted private key does not match original")
	}
}

func TestDecryptCredentialData(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("generating AES key: %v", err)
	}

	plaintext := []byte("hunter2")

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	ciphertext := aesGCMSeal(t, aesKey, nonce, plaintext)
	encBody := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatalf("wrapping AES key: %v", err)
	}

	data := fmt.Sprintf("v2:%s:%s", encBody, base64.StdEncoding.EncodeToString(encKey))

	got, err := DecryptCredentialData(data, rsaKey)
	if err != nil {
		t.Fatalf("DecryptCredentialData: %v", err)
	}

	if got != "hunter2" {
		t.Fatalf("got password %q, want %q", got, "hunter2")
	}
}

func TestEncryptDecryptCredentialDataRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	data, err := EncryptCredentialData("hunter2", &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("EncryptCredentialData: %v", err)
	}

	got, err := DecryptCredentialData(data, rsaKey)
	if err != nil {
		t.Fatalf("DecryptCredentialData: %v", err)
	}

	if got != "hunter2" {
		t.Fatalf("got password %q, want %q", got, "hunter2")
	}
}

func TestParsePublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	got, err := ParsePublicKey(string(pemBytes))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	if !got.Equal(&rsaKey.PublicKey) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestDecryptCredentialDataInvalidFormat(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	if _, err := DecryptCredentialData("v1:foo", rsaKey); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

// TestDecryptCredentialDataV1 covers the legacy single-blob RSA-PKCS1v1.5
// format produced by PWDSafe 2.x's Encryption::encWithPub() for short
// (<=500 byte) plaintexts. Credentials created before PWDSafe's
// zero-knowledge rewrite remain in this format until they are next saved.
func TestDecryptCredentialDataV1(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	plaintext := []byte("hunter2")

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encrypting credential data: %v", err)
	}

	data := base64.StdEncoding.EncodeToString(ciphertext)

	got, err := DecryptCredentialData(data, rsaKey)
	if err != nil {
		t.Fatalf("DecryptCredentialData: %v", err)
	}

	if got != "hunter2" {
		t.Fatalf("got password %q, want %q", got, "hunter2")
	}
}

// TestDecryptCredentialDataV1Chunked covers the legacy "-"-joined chunked
// RSA-PKCS1v1.5 format used by Encryption::encWithPub() for plaintexts
// longer than 500 bytes. Each chunk is independently encrypted and
// base64-encoded, and the result is prefixed with "-" per chunk, e.g.
// "-chunk1-chunk2".
func TestDecryptCredentialDataV1Chunked(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	chunks := []string{
		"this is the first chunk of a long note ",
		"and this is the second chunk of it",
	}

	var data string
	for _, chunk := range chunks {
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, []byte(chunk))
		if err != nil {
			t.Fatalf("encrypting credential data: %v", err)
		}

		data += "-" + base64.StdEncoding.EncodeToString(ciphertext)
	}

	got, err := DecryptCredentialData(data, rsaKey)
	if err != nil {
		t.Fatalf("DecryptCredentialData: %v", err)
	}

	want := chunks[0] + chunks[1]
	if got != want {
		t.Fatalf("got note %q, want %q", got, want)
	}
}
