package sshmanage

import (
	"strings"
	"testing"

	v2 "github.com/komari-monitor/komari/protocol/v2"
)

const (
	testEd25519   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAHWcDI8do/tbdscczcEcjA1QUmsTqjPtOw0MOEUmjiZ alice@laptop"
	testEd25519FP = "SHA256:w87qwnJxn5SJSLnQ2tED10xlaDoJLIWW8pikpUw3OpI"
	testRSA       = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjRZEdm3IzsaqS3eqd97o03TY+G0ASIwKoKUwMUiwyhdUnYhkGMx5TT+grrSZvdAjiH9+n7new9QU4VwmV0CuEBqi7h3jd2pTUeJsIZjGL+8T8N+geLQZzu3BPZyD6CON91BgDiNRawso8JGXmAC7XoNXLiGriub/dmq3ugbcn0CzxreLQVd3rorNeOFbaUuCbKowLCezQoGaELP9PET0BJMvbcsozPGKwu02181ENK7hHWE6GH7vadEoQYtLMkWxLhB/SoBq3m/1kjUU4w4rXBgS7bvVivf2aZOtLJ4bUVlN5WUDWSeKC+d/j2pbzMQCJFqvizhu14uF9/00pBoat bob"
	testRSAFP     = "SHA256:WHdfKiqJ7kXVTPEJdgCW4aGwuED6vxF3NQh792yPd+U"
)

func TestParsePublicKey(t *testing.T) {
	for line, fp := range map[string]string{testEd25519: testEd25519FP, testRSA: testRSAFP} {
		k, err := ParsePublicKey(line)
		if err != nil {
			t.Fatal(err)
		}
		if k.Fingerprint != fp {
			t.Errorf("fingerprint %s, want %s", k.Fingerprint, fp)
		}
		if KeyLine(k) != line {
			t.Errorf("key line %q", KeyLine(k))
		}
	}
	rsaBlob := strings.Fields(testRSA)[1]
	for _, bad := range []string{"", "ssh-ed25519", "ssh-ed25519 !!!", "ssh-ed25519 " + rsaBlob, "x509 " + rsaBlob} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestNormalizeChanges(t *testing.T) {
	yes := true
	ch, err := NormalizeChanges(v2.SSHChanges{
		AddKeys:           []string{"  " + testEd25519 + "  ", "", "# comment", testEd25519, "ssh-rsa   " + strings.Fields(testRSA)[1] + "   bob"},
		RemoveKeys:        []string{" " + testRSAFP},
		Port:              2222,
		RootPasswordLogin: &yes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.AddKeys) != 2 || ch.AddKeys[0] != testEd25519 || ch.AddKeys[1] != testRSA {
		t.Fatalf("add keys %q", ch.AddKeys)
	}
	if len(ch.RemoveKeys) != 1 || ch.RemoveKeys[0] != testRSAFP || ch.Port != 2222 || ch.RootPasswordLogin != &yes {
		t.Fatalf("changes %+v", ch)
	}

	for _, bad := range []v2.SSHChanges{
		{},
		{AddKeys: []string{"ssh-ed25519 AAAA"}},
		{RemoveKeys: []string{"MD5:aa:bb"}},
		{Port: 70000},
	} {
		if _, err := NormalizeChanges(bad); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
}
