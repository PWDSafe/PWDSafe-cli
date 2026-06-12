// Package vaultkey derives PBKDF2-based key material from the vault master
// password: the login_hash sent to /api/auth/login for accounts that use a
// derived login credential (uses_login_hash = true), and the vault key used
// to decrypt vault_data.encrypted_privkey. See package vaultcrypto for
// private key and credential decryption.
package vaultkey

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

const (
	vaultKeyIterations = 600_000
	vaultKeyLength     = 32
	loginHashLength    = 32
)

// DeriveVaultKey computes the PBKDF2-derived AES-256 vault key for the given
// password and hex-encoded salt:
//
//	vault_key = PBKDF2-HMAC-SHA256(password, salt, 600000, 32)
//
// This is both an intermediate step of DeriveLoginHash and the key used to
// decrypt vault_data.encrypted_privkey.
func DeriveVaultKey(password, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}

	return pbkdf2.Key([]byte(password), salt, vaultKeyIterations, vaultKeyLength, sha256.New), nil
}

// DeriveLoginHash computes the hex-encoded login_hash for the given password
// and hex-encoded PBKDF2 salt, matching deriveLoginHash() in
// resources/js/vault.js:
//
//	vault_key  = PBKDF2-HMAC-SHA256(password, salt, 600000, 32)
//	login_hash = hex(PBKDF2-HMAC-SHA256(key=vault_key, salt=password, 1, 32))
//
// Used when uses_login_hash is true and the account does not have a separate
// vault password.
func DeriveLoginHash(password, saltHex string) (string, error) {
	vaultKey, err := DeriveVaultKey(password, saltHex)
	if err != nil {
		return "", err
	}

	loginHash := pbkdf2.Key(vaultKey, []byte(password), 1, loginHashLength, sha256.New)

	return hex.EncodeToString(loginHash), nil
}

// DeriveLoginHashIndependent computes the hex-encoded login_hash for accounts
// with a separate vault password, matching deriveLoginHashIndependent() in
// resources/js/vault.js:
//
//	login_hash = hex(PBKDF2-HMAC-SHA256(loginPassword, login_salt, 600000, 32))
//
// Used when separate_vault_password is true and a login_salt is present.
func DeriveLoginHashIndependent(loginPassword, loginSaltHex string) (string, error) {
	salt, err := hex.DecodeString(loginSaltHex)
	if err != nil {
		return "", err
	}

	loginHash := pbkdf2.Key([]byte(loginPassword), salt, vaultKeyIterations, vaultKeyLength, sha256.New)

	return hex.EncodeToString(loginHash), nil
}
