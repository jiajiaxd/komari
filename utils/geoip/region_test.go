package geoip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupRegionFallsBackAndCaches(t *testing.T) {
	ipAPIHits, ipWhoHits := 0, 0
	ipAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipAPIHits++
		w.Write([]byte(`{"status":"fail","message":"quota exceeded"}`))
	}))
	defer ipAPI.Close()
	ipWho := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipWhoHits++
		w.Write([]byte(`{"success":true,"country":"中国","country_code":"CN","region":"广东省","region_code":"gd","city":"广州","connection":{"isp":"Chinanet"}}`))
	}))
	defer ipWho.Close()

	oldAPI, oldWho := ipAPIRegionURL, ipWhoRegionURL
	ipAPIRegionURL, ipWhoRegionURL = ipAPI.URL+"/%s", ipWho.URL+"/%s"
	defer func() { ipAPIRegionURL, ipWhoRegionURL = oldAPI, oldWho }()
	regionCache.Flush()

	ip := net.ParseIP("113.108.0.1")
	for i := 0; i < 2; i++ {
		info, err := LookupRegion(ip)
		if err != nil {
			t.Fatal(err)
		}
		if info.CountryCode != "CN" || info.RegionCode != "GD" || info.ISP != "Chinanet" || info.Source != "ipwho.is" {
			t.Fatalf("got %+v", info)
		}
	}
	if ipAPIHits != 1 || ipWhoHits != 1 {
		t.Fatalf("hits ip-api=%d ipwho=%d, want 1/1 (second lookup cached)", ipAPIHits, ipWhoHits)
	}
}

func TestLookupRegionIPAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","country":"美国","countryCode":"US","region":"VA","regionName":"弗吉尼亚州","city":"Ashburn","isp":"Google LLC"}`))
	}))
	defer srv.Close()
	old := ipAPIRegionURL
	ipAPIRegionURL = srv.URL + "/%s"
	defer func() { ipAPIRegionURL = old }()
	regionCache.Flush()

	info, err := LookupRegion(net.ParseIP("8.8.8.8"))
	if err != nil || info.CountryCode != "US" || info.RegionCode != "VA" || info.Region != "弗吉尼亚州" {
		t.Fatalf("got %+v, %v", info, err)
	}
}
