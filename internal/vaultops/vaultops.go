// Package vaultops contains higher-level vault operations shared between
// the CLI and TUI, built on top of internal/api and internal/vaultcrypto.
package vaultops

import (
	"fmt"

	"pwdsafe-cli/internal/api"
	"pwdsafe-cli/internal/vaultcrypto"
)

// EncryptForGroup fetches the public keys of every member of groupID and
// encrypts plaintext for each of them, producing the per-member entries
// required by api.CreateCredentialRequest.Encrypted.
func EncryptForGroup(client *api.Client, groupID int, plaintext string) ([]api.EncryptedEntry, error) {
	members, err := client.GroupPubkeys(groupID)
	if err != nil {
		return nil, fmt.Errorf("fetching group members: %w", err)
	}

	entries := make([]api.EncryptedEntry, 0, len(members))

	for _, member := range members {
		pub, err := vaultcrypto.ParsePublicKey(member.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("parsing public key for user %d: %w", member.ID, err)
		}

		data, err := vaultcrypto.EncryptCredentialData(plaintext, pub)
		if err != nil {
			return nil, fmt.Errorf("encrypting for user %d: %w", member.ID, err)
		}

		entries = append(entries, api.EncryptedEntry{UserID: member.ID, Data: data})
	}

	return entries, nil
}
