// Package totp generates RFC 6238 TOTP codes from a base32-encoded secret.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Generate computes the current 6-digit TOTP code for the given base32-encoded
// secret and returns the seconds remaining before the code rolls over.
func Generate(secret string) (code string, secondsLeft int, err error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", 0, fmt.Errorf("decoding TOTP secret: %w", err)
		}
	}

	now := time.Now().Unix()
	counter := uint64(now / 30)
	secondsLeft = int(30 - now%30)

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	binCode := (int(h[offset])&0x7f)<<24 |
		(int(h[offset+1])&0xff)<<16 |
		(int(h[offset+2])&0xff)<<8 |
		(int(h[offset+3]) & 0xff)

	return fmt.Sprintf("%06d", binCode%1_000_000), secondsLeft, nil
}
