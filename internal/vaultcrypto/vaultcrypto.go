// Package vaultcrypto decrypts the user's RSA private key
// (vault_data.encrypted_privkey) and credential data blobs
// (Credential.data), per the algorithms described in
// app/Helpers/Encryption.php and resources/js/vault.js of the PWDSafe
// server: PBKDF2-SHA256 for key derivation (see package vaultkey),
// AES-256-GCM for symmetric encryption, and RSA-OAEP-SHA256 for wrapping
// per-credential AES keys.
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
	"errors"
	"fmt"
	"strings"
)

const gcmNonceSize = 12

// DecryptPrivateKey decrypts vault_data.encrypted_privkey using the vault
// key derived by vaultkey.DeriveVaultKey. encrypted_privkey is
// base64(iv[12] || AES-256-GCM(privkey_der) || tag[16]).
func DecryptPrivateKey(encryptedPrivKeyB64 string, vaultKey []byte) (*rsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedPrivKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted_privkey: %w", err)
	}

	if len(raw) < gcmNonceSize {
		return nil, errors.New("encrypted_privkey is too short")
	}

	nonce, ciphertext := raw[:gcmNonceSize], raw[gcmNonceSize:]

	plaintext, err := aesGCMOpen(vaultKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting private key: %w", err)
	}

	der := plaintext
	if block, _ := pem.Decode(plaintext); block != nil {
		der = block.Bytes
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not an RSA key (got %T)", key)
		}

		return rsaKey, nil
	}

	if rsaKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return rsaKey, nil
	}

	return nil, errors.New("private key is not a valid PKCS#8 or PKCS#1 RSA key")
}

// DecryptCredentialData decrypts a Credential.data blob and returns the
// decrypted plaintext (the raw password, not JSON-encoded).
//
// Two formats are supported:
//   - v2: "v2:base64(iv[12] || aes_ciphertext || tag[16]):base64(rsa_oaep_sha256(aes_key))",
//     produced by every credential created or re-saved since PWDSafe's
//     zero-knowledge rewrite.
//   - v1 (legacy): plain RSA-PKCS1v1.5, base64-encoded. Plaintext longer
//     than 500 bytes is split into multiple chunks, each encrypted and
//     base64-encoded separately, joined with "-". Servers upgraded from
//     PWDSafe 2.x will still have credentials in this format until they
//     are next changed.
func DecryptCredentialData(data string, privKey *rsa.PrivateKey) (string, error) {
	if strings.HasPrefix(data, "v2:") {
		return decryptCredentialDataV2(data, privKey)
	}

	return decryptCredentialDataV1(data, privKey)
}

func decryptCredentialDataV2(data string, privKey *rsa.PrivateKey) (string, error) {
	parts := strings.Split(data, ":")
	if len(parts) != 3 || parts[0] != "v2" {
		return "", fmt.Errorf("unsupported credential data format")
	}

	encBody, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding credential ciphertext: %w", err)
	}

	encKey, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decoding wrapped AES key: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encKey, nil)
	if err != nil {
		return "", fmt.Errorf("unwrapping AES key: %w", err)
	}

	if len(encBody) < gcmNonceSize {
		return "", errors.New("credential ciphertext is too short")
	}

	nonce, ciphertext := encBody[:gcmNonceSize], encBody[gcmNonceSize:]

	plaintext, err := aesGCMOpen(aesKey, nonce, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting credential data: %w", err)
	}

	return string(plaintext), nil
}

// decryptCredentialDataV1 decrypts the legacy single-blob or "-"-joined
// chunked RSA-PKCS1v1.5 format produced by PWDSafe 2.x's
// Encryption::encWithPub().
func decryptCredentialDataV1(data string, privKey *rsa.PrivateKey) (string, error) {
	var plaintext []byte

	for _, chunk := range strings.Split(data, "-") {
		if chunk == "" {
			continue
		}

		ciphertext, err := base64.StdEncoding.DecodeString(chunk)
		if err != nil {
			return "", fmt.Errorf("decoding credential ciphertext: %w", err)
		}

		part, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
		if err != nil {
			return "", fmt.Errorf("decrypting credential data: %w", err)
		}

		plaintext = append(plaintext, part...)
	}

	if len(plaintext) == 0 {
		return "", errors.New("credential ciphertext is empty")
	}

	return string(plaintext), nil
}

// ParsePublicKey parses a PEM-encoded RSA public key (SubjectPublicKeyInfo),
// as returned by GET /api/groups/{group}/pubkeys.
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key (got %T)", pub)
	}

	return rsaPub, nil
}

// EncryptCredentialData encrypts plaintext for pubKey, producing a blob in
// the format DecryptCredentialData expects:
// "v2:base64(iv[12] || aes_ciphertext || tag[16]):base64(rsa_oaep_sha256(aes_key))".
// A fresh random AES-256 key and nonce are generated for every call.
func EncryptCredentialData(plaintext string, pubKey *rsa.PublicKey) (string, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("generating AES key: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext, err := sealAESGCM(aesKey, nonce, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("encrypting credential data: %w", err)
	}

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("wrapping AES key: %w", err)
	}

	body := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
	wrapped := base64.StdEncoding.EncodeToString(encKey)

	return "v2:" + body + ":" + wrapped, nil
}

func sealAESGCM(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesGCMOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}
