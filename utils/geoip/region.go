package geoip

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// RegionInfo 是精确到省/州一级的 IP 属地信息。RegionCode 为 ISO 3166-2 子区域代码
// （不含国家前缀），如中国广东为 "GD"、美国加州为 "CA"。
type RegionInfo struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	RegionCode  string `json:"region_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Source      string `json:"source"`
}

var (
	regionCache      = cache.New(48*time.Hour, time.Hour)
	regionHTTPClient = &http.Client{Timeout: 5 * time.Second}

	// 免费、无需密钥的区域级属地接口，按顺序回退。可在测试中替换。
	ipAPIRegionURL  = "http://ip-api.com/json/%s?lang=zh-CN&fields=status,message,country,countryCode,region,regionName,city,isp"
	ipWhoRegionURL  = "https://ipwho.is/%s?lang=zh-CN&fields=success,message,country,country_code,region,region_code,city,connection"
	regionProviders = []func(net.IP) (*RegionInfo, error){lookupRegionIPAPI, lookupRegionIPWho}
)

// LookupRegion 查询 IP 的国家/省州/城市。依次尝试 ip-api.com 与 ipwho.is，成功结果缓存 48 小时。
// 与 GetGeoInfo 使用的国家级 provider 相互独立。
func LookupRegion(ip net.IP) (*RegionInfo, error) {
	if ip == nil {
		return nil, errors.New("invalid ip")
	}
	key := ip.String()
	if cached, ok := regionCache.Get(key); ok {
		return cached.(*RegionInfo), nil
	}
	var errs []error
	for _, provider := range regionProviders {
		info, err := provider(ip)
		if err == nil && info != nil && info.CountryCode != "" {
			info.CountryCode = strings.ToUpper(info.CountryCode)
			info.RegionCode = strings.ToUpper(info.RegionCode)
			regionCache.Set(key, info, cache.DefaultExpiration)
			return info, nil
		}
		if err == nil {
			err = errors.New("empty result")
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func getRegionJSON(rawURL string, target any) error {
	resp, err := regionHTTPClient.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func lookupRegionIPAPI(ip net.IP) (*RegionInfo, error) {
	var r struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Region      string `json:"region"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := getRegionJSON(fmt.Sprintf(ipAPIRegionURL, url.PathEscape(ip.String())), &r); err != nil {
		return nil, fmt.Errorf("ip-api.com: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("ip-api.com: %s", r.Message)
	}
	return &RegionInfo{
		CountryCode: r.CountryCode,
		Country:     r.Country,
		RegionCode:  r.Region,
		Region:      r.RegionName,
		City:        r.City,
		ISP:         r.ISP,
		Source:      "ip-api.com",
	}, nil
}

func lookupRegionIPWho(ip net.IP) (*RegionInfo, error) {
	var r struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		RegionCode  string `json:"region_code"`
		City        string `json:"city"`
		Connection  struct {
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := getRegionJSON(fmt.Sprintf(ipWhoRegionURL, url.PathEscape(ip.String())), &r); err != nil {
		return nil, fmt.Errorf("ipwho.is: %w", err)
	}
	if !r.Success {
		return nil, fmt.Errorf("ipwho.is: %s", r.Message)
	}
	return &RegionInfo{
		CountryCode: r.CountryCode,
		Country:     r.Country,
		RegionCode:  r.RegionCode,
		Region:      r.Region,
		City:        r.City,
		ISP:         r.Connection.ISP,
		Source:      "ipwho.is",
	}, nil
}
