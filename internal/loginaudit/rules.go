package loginaudit

import (
	"net"
	"strings"
)

// 可信原因
const (
	ReasonPrivate   = "private"
	ReasonServer    = "server"
	ReasonWhitelist = "whitelist"
	ReasonRegion    = "region"
)

// cgnat 为运营商级 NAT / Tailscale 等使用的共享地址段，同样不可公网路由。
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == '，' || r == '；' || r == '、'
	})
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// ParseTrustedIPs 解析可信 IP/CIDR 列表，单个 IP 视为 /32 或 /128，返回无法解析的条目。
func ParseTrustedIPs(s string) (nets []*net.IPNet, invalid []string) {
	for _, item := range splitList(s) {
		if _, n, err := net.ParseCIDR(item); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		invalid = append(invalid, item)
	}
	return nets, invalid
}

// ParseRegions 解析可信属地列表：国家代码（CN）或国家-省州代码（CN-GD、US-CA），大小写不敏感。
func ParseRegions(s string) map[string]struct{} {
	regions := make(map[string]struct{})
	for _, item := range splitList(s) {
		item = strings.ToUpper(strings.ReplaceAll(item, "_", "-"))
		regions[item] = struct{}{}
	}
	return regions
}

type rules struct {
	serverIPs map[string]struct{}
	trusted   []*net.IPNet
	regions   map[string]struct{}
}

func (r rules) matchRegion(countryCode, regionCode string) bool {
	if countryCode == "" {
		return false
	}
	if _, ok := r.regions[countryCode]; ok {
		return true
	}
	if regionCode == "" {
		return false
	}
	_, ok := r.regions[countryCode+"-"+regionCode]
	return ok
}

// trustWithoutGeo 判断无需属地信息即可确定的可信来源。
func (r rules) trustWithoutGeo(ip net.IP) string {
	if isPrivateIP(ip) {
		return ReasonPrivate
	}
	if _, ok := r.serverIPs[normalizeIP(ip)]; ok {
		return ReasonServer
	}
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return ReasonWhitelist
		}
	}
	return ""
}
