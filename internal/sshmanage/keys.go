package sshmanage

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	v2 "github.com/komari-monitor/komari/protocol/v2"
)

var keyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-dss":                            true,
	"ssh-ed25519":                        true,
	"ssh-ed448":                          true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// ParsePublicKey validates one OpenSSH public key line ("type base64
// [comment]") and computes its SHA256 fingerprint as ssh-keygen prints it.
func ParsePublicKey(line string) (v2.SSHAuthorizedKey, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return v2.SSHAuthorizedKey{}, errors.New("expected \"<type> <base64> [comment]\"")
	}
	keyType := fields[0]
	if !keyTypes[keyType] {
		return v2.SSHAuthorizedKey{}, fmt.Errorf("unsupported key type %q", keyType)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(raw) < 4 {
		return v2.SSHAuthorizedKey{}, errors.New("invalid key data")
	}
	n := binary.BigEndian.Uint32(raw)
	if uint64(n)+4 > uint64(len(raw)) || string(raw[4:4+n]) != keyType {
		return v2.SSHAuthorizedKey{}, errors.New("key data does not match key type")
	}
	sum := sha256.Sum256(raw)
	return v2.SSHAuthorizedKey{
		Type:        keyType,
		Key:         fields[1],
		Comment:     strings.Join(fields[2:], " "),
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}, nil
}

// KeyLine renders a key the way it is written to authorized_keys.
func KeyLine(k v2.SSHAuthorizedKey) string {
	line := k.Type + " " + k.Key
	if k.Comment != "" {
		line += " " + k.Comment
	}
	return line
}
