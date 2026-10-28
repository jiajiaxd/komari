package sshmanage

import (
	"strings"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	v2 "github.com/komari-monitor/komari/protocol/v2"
)

func TestNormalizeRemark(t *testing.T) {
	fp, remark, err := NormalizeRemark(" "+testEd25519FP+" ", "  我的电脑  ")
	if err != nil || fp != testEd25519FP || remark != "我的电脑" {
		t.Fatalf("normalize: %q %q %v", fp, remark, err)
	}
	for _, input := range []struct{ fp, remark string }{
		{"SHA256:" + strings.Repeat("!", 43), "test"},
		{"MD5:abcd", "test"},
		{testEd25519FP, "a\nb"},
		{testEd25519FP, "a\x00b"},
		{testEd25519FP, strings.Repeat("字", 201)},
	} {
		if _, _, err := NormalizeRemark(input.fp, input.remark); err == nil {
			t.Errorf("accepted invalid remark: %+v", input)
		}
	}
	if _, _, err := NormalizeRemark(testEd25519FP, strings.Repeat("字", 200)); err != nil {
		t.Fatal(err)
	}
}

func TestRemarksSurviveRefreshAndCanBeCleared(t *testing.T) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:ssh_remark_test?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()
	t.Cleanup(func() {
		db.Where("1 = 1").Delete(&models.SSHKeyRemark{})
		db.Where("1 = 1").Delete(&models.SSHState{})
	})
	key, err := ParsePublicKey(testEd25519)
	if err != nil {
		t.Fatal(err)
	}
	for _, remark := range []string{"Laptop", "工作电脑"} {
		if err := SetRemark(key.Fingerprint, remark); err != nil {
			t.Fatal(err)
		}
		// Reads from different nodes and a failed read must not replace remarks.
		for _, uuid := range []string{"node-1", "node-2"} {
			save(uuid, &v2.SSHState{Keys: []v2.SSHAuthorizedKey{key}}, "")
		}
		save("node-1", nil, "timeout")
		remarks, err := ListRemarks()
		if err != nil || remarks[key.Fingerprint] != remark || len(remarks) != 1 {
			t.Fatalf("remarks after refresh: %v, %v", remarks, err)
		}
	}
	if err := SetRemark(key.Fingerprint, ""); err != nil {
		t.Fatal(err)
	}
	remarks, err := ListRemarks()
	if err != nil || len(remarks) != 0 {
		t.Fatalf("clear remark: %v, %v", remarks, err)
	}
	entries, err := List()
	if err != nil || len(entries) != 2 {
		t.Fatalf("list snapshots: %v, %v", entries, err)
	}
	for _, entry := range entries {
		if entry.State == nil || entry.State.Keys[0].Comment != key.Comment {
			t.Fatalf("original key comment changed: %+v", entry)
		}
	}
}
