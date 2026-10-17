package loginaudit

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/utils/geoip"
)

func setupDB(t *testing.T) {
	t.Helper()
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:loginaudit_test?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()
	db.Where("1 = 1").Delete(&models.LoginRecord{})
	db.Where("1 = 1").Delete(&models.Client{})
	InvalidateServerIPs()
}

func TestParseRegionsAndTrustedIPs(t *testing.T) {
	regions := ParseRegions("cn-gd, US_CA；JP\nus-ny")
	for _, want := range []string{"CN-GD", "US-CA", "US-NY"} {
		if _, ok := regions[want]; !ok {
			t.Fatalf("missing %s in %v", want, regions)
		}
	}
	nets, invalid := ParseTrustedIPs("203.0.113.0/24, 198.51.100.7\n2001:db8::/32,bad")
	if len(nets) != 3 || len(invalid) != 1 || invalid[0] != "bad" {
		t.Fatalf("nets=%v invalid=%v", nets, invalid)
	}
}

func TestRulesMatching(t *testing.T) {
	trusted, _ := ParseTrustedIPs("203.0.113.0/24")
	r := rules{
		serverIPs: map[string]struct{}{"198.51.100.1": {}, "2001:db8::1": {}},
		trusted:   trusted,
		regions:   ParseRegions("CN-GD,JP"),
	}
	cases := map[string]string{
		"10.1.2.3":      ReasonPrivate,
		"127.0.0.1":     ReasonPrivate,
		"100.100.1.1":   ReasonPrivate,
		"fe80::1":       ReasonPrivate,
		"198.51.100.1":  ReasonServer,
		"2001:db8::1":   ReasonServer,
		"203.0.113.200": ReasonWhitelist,
		"8.8.8.8":       "",
	}
	for ip, want := range cases {
		if got := r.trustWithoutGeo(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	if !r.matchRegion("CN", "GD") || r.matchRegion("CN", "BJ") || !r.matchRegion("JP", "13") || r.matchRegion("", "") {
		t.Fatal("region matching mismatch")
	}
}

func TestProcessClassifiesStoresAndAlerts(t *testing.T) {
	setupDB(t)
	db := dbcore.GetDBInstance()
	db.Create(&models.Client{UUID: "c1", Token: "t1", Name: "node-1", IPv4: "198.51.100.1"})
	if err := config.SetMany(map[string]any{
		config.LoginMonitorEnabledKey: true,
		config.LoginAlertEnabledKey:   true,
		config.LoginAllowedRegionsKey: "CN-GD",
		config.LoginTrustedIPsKey:     "203.0.113.0/24",
		config.NotificationEnabledKey: true,
		config.NotificationMethodKey:  "webhook",
	}); err != nil {
		t.Fatal(err)
	}

	oldLookup, oldSend := lookupRegion, sendNotice
	defer func() { lookupRegion, sendNotice = oldLookup, oldSend }()
	lookupRegion = func(ip net.IP) (*geoip.RegionInfo, error) {
		switch ip.String() {
		case "113.108.0.1":
			return &geoip.RegionInfo{CountryCode: "CN", Country: "中国", RegionCode: "GD", Region: "广东", City: "广州"}, nil
		case "8.8.8.8":
			return &geoip.RegionInfo{CountryCode: "US", Country: "美国", RegionCode: "CA", Region: "加利福尼亚州", City: "Mountain View", ISP: "Google"}, nil
		}
		return nil, errors.New("lookup failed")
	}
	var sent []models.EventMessage
	sendNotice = func(ev models.EventMessage) error {
		sent = append(sent, ev)
		return nil
	}

	at := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	for _, ip := range []string{"192.168.1.2", "198.51.100.1", "203.0.113.9", "113.108.0.1", "8.8.8.8", "1.2.3.4"} {
		process(job{uuid: "c1", event: v2.LoginEvent{Protocol: "ssh", Username: "root", SourceIP: ip, SourcePort: 22, Time: at}})
	}
	process(job{uuid: "unknown-client", event: v2.LoginEvent{Protocol: "ssh", SourceIP: "8.8.8.8"}})

	records, total, err := List(ListOptions{Limit: 100, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 {
		t.Fatalf("total = %d, want 6", total)
	}
	got := map[string]models.LoginRecord{}
	for _, r := range records {
		got[r.SourceIP] = r
	}
	expect := map[string]string{"192.168.1.2": ReasonPrivate, "198.51.100.1": ReasonServer, "203.0.113.9": ReasonWhitelist, "113.108.0.1": ReasonRegion, "8.8.8.8": "", "1.2.3.4": ""}
	for ip, reason := range expect {
		r := got[ip]
		if r.TrustReason != reason || r.Trusted != (reason != "") || r.Alerted != (reason == "") {
			t.Errorf("%s: %+v", ip, r)
		}
	}
	if got["8.8.8.8"].Region != "加利福尼亚州" || got["8.8.8.8"].ClientName != "node-1" {
		t.Errorf("location not stored: %+v", got["8.8.8.8"])
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d notifications, want 2", len(sent))
	}
	untrusted, total, _ := List(ListOptions{Limit: 10, Page: 1, UntrustedOnly: true})
	if total != 2 || len(untrusted) != 2 {
		t.Fatalf("untrusted total = %d", total)
	}

	// 关闭后不再记录
	config.Set(config.LoginMonitorEnabledKey, false)
	process(job{uuid: "c1", event: v2.LoginEvent{Protocol: "ssh", SourceIP: "8.8.4.4"}})
	if _, total, _ := List(ListOptions{Limit: 10, Page: 1}); total != 6 {
		t.Fatalf("recorded while disabled, total = %d", total)
	}
	config.Set(config.LoginMonitorEnabledKey, true)
}

func TestCleanupByAgeAndCount(t *testing.T) {
	setupDB(t)
	db := dbcore.GetDBInstance()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		db.Create(&models.LoginRecord{ClientUUID: "c1", SourceIP: "8.8.8.8", LoginTime: now.Add(-time.Duration(i) * time.Hour)})
	}
	db.Create(&models.LoginRecord{ClientUUID: "c1", SourceIP: "old", LoginTime: now.AddDate(0, 0, -400)})

	if err := cleanup(365, 1000, now); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := List(ListOptions{Limit: 100, Page: 1}); total != 10 {
		t.Fatalf("after age cleanup total = %d, want 10", total)
	}
	if err := cleanup(365, 3, now); err != nil {
		t.Fatal(err)
	}
	records, total, _ := List(ListOptions{Limit: 100, Page: 1})
	if total != 3 {
		t.Fatalf("after count cleanup total = %d, want 3", total)
	}
	if !records[0].LoginTime.Equal(now) || !records[2].LoginTime.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("kept wrong records: %+v", records)
	}
	if n, err := Clear("c1"); err != nil || n != 3 {
		t.Fatalf("clear = %d, %v", n, err)
	}
}

func TestEnqueueNeverBlocks(t *testing.T) {
	events := make([]v2.LoginEvent, MaxEventsPerBatch+10)
	if n := Enqueue("c1", events); n != MaxEventsPerBatch {
		t.Fatalf("accepted %d", n)
	}
	for len(jobs) > 0 {
		<-jobs
	}
}

func TestFormatMessage(t *testing.T) {
	msg := formatMessage(models.LoginRecord{Protocol: "rdp", ClientName: "win", Username: `HOST\admin`, SourceIP: "2001:db8::2", SourcePort: 3389,
		Country: "美国", Region: "弗吉尼亚州", City: "Ashburn", ISP: "Google", LoginTime: time.Now()})
	for _, want := range []string{"RDP", "[2001:db8::2]:3389", "美国 弗吉尼亚州 Ashburn (Google)", `HOST\admin`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
}
