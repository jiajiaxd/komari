// Package loginaudit 处理 agent 上报的 SSH/RDP 登录：判断来源是否可信、查询 IP 属地、
// 写入登录历史，并对非可信来源发送通知。所有处理都在后台 worker 中进行，
// 上报接口只负责入队，不会被属地查询或通知发送阻塞。
package loginaudit

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	messageevent "github.com/komari-monitor/komari/database/models/messageEvent"
	"github.com/komari-monitor/komari/internal/config"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/utils/geoip"
	logger "github.com/komari-monitor/komari/utils/log"
	"github.com/komari-monitor/komari/utils/messageSender"
)

const (
	queueSize = 1024
	// MaxEventsPerBatch 单次上报最多接受的事件数
	MaxEventsPerBatch = 50
	serverIPCacheTTL  = time.Minute
)

type settings struct {
	Enabled          bool   `json:"login_monitor_enabled" default:"true"`
	AlertEnabled     bool   `json:"login_alert_enabled" default:"true"`
	AllowedRegions   string `json:"login_allowed_regions" default:""`
	TrustedIPs       string `json:"login_trusted_ips" default:""`
	RetentionDays    int    `json:"login_history_retention_days" default:"365"`
	MaxRecords       int    `json:"login_history_max_records" default:"1000"`
	NotificationOn   bool   `json:"notification_enabled" default:"true"`
	NotificationType string `json:"notification_method" default:"none"`
}

type job struct {
	uuid  string
	event v2.LoginEvent
}

var (
	jobs = make(chan job, queueSize)

	// 可在测试中替换
	lookupRegion = geoip.LookupRegion
	sendNotice   = messageSender.SendNotification

	serverIPMu      sync.Mutex
	serverIPs       map[string]struct{}
	serverIPExpires time.Time
)

// Enqueue 将登录事件放入后台队列，从不阻塞；返回实际接受的条数。
func Enqueue(uuid string, events []v2.LoginEvent) int {
	if len(events) > MaxEventsPerBatch {
		events = events[:MaxEventsPerBatch]
	}
	accepted := 0
	for _, ev := range events {
		select {
		case jobs <- job{uuid: uuid, event: ev}:
			accepted++
		default:
			logger.Warn("loginaudit", "queue full, dropping login event", "client", uuid, "ip", ev.SourceIP)
		}
	}
	return accepted
}

// Start 启动后台 worker，返回停止函数。
func Start() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-jobs:
				func() {
					defer func() {
						if r := recover(); r != nil {
							logger.Error("loginaudit", "panic while processing login event", "panic", r)
						}
					}()
					process(j)
				}()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func loadSettings() (*settings, error) {
	return config.GetManyAs[settings]()
}

func process(j job) {
	cfg, err := loadSettings()
	if err != nil {
		logger.Error("loginaudit", "failed to load settings", "error", err)
		return
	}
	if !cfg.Enabled {
		return
	}
	ev := j.event
	ip := net.ParseIP(strings.TrimSpace(ev.SourceIP))
	if ip == nil {
		logger.Warn("loginaudit", "ignoring login event with invalid source ip", "client", j.uuid, "ip", ev.SourceIP)
		return
	}
	client, err := clients.GetClientByUUID(j.uuid)
	if err != nil {
		return
	}

	loginTime := ev.Time.UTC()
	if loginTime.IsZero() || loginTime.After(time.Now().Add(time.Hour)) {
		loginTime = time.Now().UTC()
	}
	record := models.LoginRecord{
		ClientUUID: client.UUID,
		ClientName: client.Name,
		Protocol:   truncate(strings.ToLower(ev.Protocol), 10),
		Username:   truncate(ev.Username, 255),
		SourceIP:   normalizeIP(ip),
		SourcePort: ev.SourcePort,
		AuthMethod: truncate(ev.AuthMethod, 64),
		LoginTime:  loginTime,
	}

	r := currentRules(cfg)
	reason := r.trustWithoutGeo(ip)
	if reason != ReasonPrivate {
		if info, err := lookupRegion(ip); err == nil {
			record.Country = truncate(info.Country, 100)
			record.CountryCode = truncate(info.CountryCode, 8)
			record.Region = truncate(info.Region, 100)
			record.RegionCode = truncate(info.RegionCode, 16)
			record.City = truncate(info.City, 100)
			record.ISP = truncate(info.ISP, 255)
			if reason == "" && r.matchRegion(info.CountryCode, info.RegionCode) {
				reason = ReasonRegion
			}
		} else {
			logger.Warn("loginaudit", "ip location lookup failed", "ip", record.SourceIP, "error", err)
		}
	}
	record.Trusted = reason != ""
	record.TrustReason = reason

	db := dbcore.GetDBInstance()
	if err := db.Create(&record).Error; err != nil {
		logger.Error("loginaudit", "failed to save login record", "error", err)
		return
	}
	if record.Trusted || !cfg.AlertEnabled || !cfg.NotificationOn || cfg.NotificationType == "" || cfg.NotificationType == "none" {
		return
	}
	err = sendNotice(models.EventMessage{
		Event:   messageevent.RemoteLogin,
		Clients: []models.Client{{UUID: client.UUID}},
		Time:    loginTime,
		Message: formatMessage(record),
		Emoji:   "🚨",
	})
	if err != nil {
		logger.Warn("loginaudit", "failed to send login alert", "error", err)
		return
	}
	db.Model(&models.LoginRecord{}).Where("id = ?", record.ID).Update("alerted", true)
}

func currentRules(cfg *settings) rules {
	trusted, _ := ParseTrustedIPs(cfg.TrustedIPs)
	return rules{
		serverIPs: currentServerIPs(),
		trusted:   trusted,
		regions:   ParseRegions(cfg.AllowedRegions),
	}
}

// currentServerIPs 返回所有已添加节点的 IPv4/IPv6，缓存 1 分钟以避免每次登录全表扫描。
func currentServerIPs() map[string]struct{} {
	serverIPMu.Lock()
	defer serverIPMu.Unlock()
	if serverIPs != nil && time.Now().Before(serverIPExpires) {
		return serverIPs
	}
	all, err := clients.GetAllClientBasicInfo()
	if err != nil {
		logger.Error("loginaudit", "failed to load client ips", "error", err)
		if serverIPs != nil {
			return serverIPs
		}
		return map[string]struct{}{}
	}
	set := make(map[string]struct{})
	for _, c := range all {
		for _, item := range splitList(c.IPv4 + "," + c.IPv6) {
			if ip := net.ParseIP(item); ip != nil {
				set[normalizeIP(ip)] = struct{}{}
			}
		}
	}
	serverIPs = set
	serverIPExpires = time.Now().Add(serverIPCacheTTL)
	return set
}

// InvalidateServerIPs 在节点增删或 IP 变化后可调用以立即刷新缓存。
func InvalidateServerIPs() {
	serverIPMu.Lock()
	serverIPExpires = time.Time{}
	serverIPMu.Unlock()
}

// Location 返回记录的属地描述，如 "中国 广东 广州 (Chinanet)"。
func Location(r models.LoginRecord) string {
	parts := make([]string, 0, 3)
	for _, p := range []string{r.Country, r.Region, r.City} {
		if p != "" && (len(parts) == 0 || parts[len(parts)-1] != p) {
			parts = append(parts, p)
		}
	}
	loc := strings.Join(parts, " ")
	if loc == "" {
		loc = "unknown"
	}
	if r.ISP != "" {
		loc += " (" + r.ISP + ")"
	}
	return loc
}

func formatMessage(r models.LoginRecord) string {
	source := r.SourceIP
	if r.SourcePort > 0 {
		source = net.JoinHostPort(r.SourceIP, fmt.Sprint(r.SourcePort))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Untrusted %s login on %s\n", strings.ToUpper(r.Protocol), r.ClientName)
	fmt.Fprintf(&b, "User: %s\n", r.Username)
	fmt.Fprintf(&b, "Source IP: %s\n", source)
	fmt.Fprintf(&b, "Location: %s\n", Location(r))
	fmt.Fprintf(&b, "Login time: %s", r.LoginTime.In(time.Local).Format("2006-01-02 15:04:05 -07:00"))
	if r.AuthMethod != "" {
		fmt.Fprintf(&b, "\nAuth method: %s", r.AuthMethod)
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// 按字节截断时保持 UTF-8 完整
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
