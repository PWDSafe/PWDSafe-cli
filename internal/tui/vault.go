package tui

import "crypto/rsa"

// vaultSession holds vault key material derived once per TUI session. It is
// kept only in memory and never written to disk. It is mutated only from
// Update, which runs on a single goroutine, to avoid races with the
// goroutines that run tea.Cmd functions.
type vaultSession struct {
	vaultKey []byte
	privKey  *rsa.PrivateKey
}

func (v *vaultSession) ready() bool {
	return v != nil && v.privKey != nil
}

// wipe forgets the session's key material, forcing the next decryption to
// prompt for the master password again. The vault key bytes are zeroed
// before the references are dropped.
func (v *vaultSession) wipe() {
	for i := range v.vaultKey {
		v.vaultKey[i] = 0
	}

	v.vaultKey = nil
	v.privKey = nil
}
