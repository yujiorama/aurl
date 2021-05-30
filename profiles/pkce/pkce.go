// Package pkce provides generation of the PKCE parameters.
// See also https://tools.ietf.org/html/rfc7636.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
)

var Plain PKCE

const (
	// code challenge methods defined as https://tools.ietf.org/html/rfc7636#section-4.3
	methodS256 = "S256"
)

// PKCE represents a set of the PKCE parameters.
type PKCE struct {
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

// New generates a parameters for S256.
func New(usePKCE string) PKCE {
	if use, err := strconv.ParseBool(usePKCE); err != nil || !use {
		return Plain
	}

	b, err := random32()
	if err != nil {
		return Plain
	}
	aPKCE := computeS256(b)
	return aPKCE
}

func (pkce *PKCE) Enabled() bool {
	return pkce.CodeChallenge != ""
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return b, nil
}

func computeS256(b []byte) PKCE {
	v := base64URLEncode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(v))
	return PKCE{
		CodeChallenge:       base64URLEncode(s.Sum(nil)),
		CodeChallengeMethod: methodS256,
		CodeVerifier:        v,
	}
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
