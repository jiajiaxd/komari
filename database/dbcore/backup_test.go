package dbcore

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestZipDirectoryStoresLargeFilesWithoutCompression(t *testing.T) {
	src := t.TempDir()
	large := bytes.Repeat([]byte("metric"), zipStoreThreshold/6+1)
	small := []byte("theme config")
	if err := os.WriteFile(filepath.Join(src, "metrics.db"), large, 0o600); err != nil {
		t.Fatalf("write large fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "settings.json"), small, 0o600); err != nil {
		t.Fatalf("write small fixture: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "backup.zip")
	if err := zipDirectoryExcluding(src, dst, nil); err != nil {
		t.Fatalf("zipDirectoryExcluding: %v", err)
	}

	zr, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()
	want := map[string]struct {
		method  uint16
		content []byte
	}{
		"metrics.db":    {zip.Store, large},
		"settings.json": {zip.Deflate, small},
	}
	for _, f := range zr.File {
		w, ok := want[f.Name]
		if !ok {
			t.Fatalf("unexpected entry %q", f.Name)
		}
		delete(want, f.Name)
		if f.Method != w.method {
			t.Fatalf("%s method = %d, want %d", f.Name, f.Method, w.method)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		if !bytes.Equal(got, w.content) {
			t.Fatalf("%s content mismatch", f.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing entries: %v", want)
	}
}

func TestPruneUpgradeBackupsKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"upgrade-20261016-080000.zip",
		"upgrade-20261018-090000.zip",
		"upgrade-20261017-120000.zip",
		"upgrade-20261018-100000.zip",
		"pre-restore-20261001-000000.zip",
		"manual.zip",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	pruneUpgradeBackups(dir, 2)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	for _, name := range []string{"upgrade-20261018-090000.zip", "upgrade-20261018-100000.zip", "pre-restore-20261001-000000.zip", "manual.zip"} {
		if !got[name] {
			t.Fatalf("%s should be kept, have %v", name, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected remaining files: %v", got)
	}
}
