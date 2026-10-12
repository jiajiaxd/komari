package plugin

import (
	"github.com/komari-monitor/komari/utils"
	"testing"
)

func TestCheckKomariVersion(t *testing.T) {
	tests := []struct {
		constraint string
		wantErr    bool
	}{
		{"", false},
		{"0.0.1", false},
		{"v0.0.1", false},
		{">=0.0.1", false},
		{">0.0.1", true},
		{"<1.0.0", false},
		{"<=0.0.1", false},
		{">=99.0.0", true},
		{"0.1", true}, // 0.1.0 > 0.0.1
		{"1", true},   // 1.0.0 > 0.0.1
		{"1.2.3.4", true},
		{"abc", true},
		{">", true},
	}
	for _, tt := range tests {
		err := CheckKomariVersion(tt.constraint)
		if (err != nil) != tt.wantErr {
			t.Errorf("CheckKomariVersion(%q) error = %v, wantErr %v", tt.constraint, err, tt.wantErr)
		}
	}
}

func TestCheckForkKomariVersion(t *testing.T) {
	previous := utils.CurrentVersion
	utils.CurrentVersion = "1.5.1-fork"
	t.Cleanup(func() { utils.CurrentVersion = previous })
	for _, tc := range []struct {
		constraint string
		wantErr    bool
	}{
		{"1.5.1", false},
		{">=1.5.1", false},
		{">=99.0.0", true},
		{"<1.5.1", true},
	} {
		if err := CheckKomariVersion(tc.constraint); (err != nil) != tc.wantErr {
			t.Errorf("fork constraint %q: error=%v, wantErr=%v", tc.constraint, err, tc.wantErr)
		}
	}
}
