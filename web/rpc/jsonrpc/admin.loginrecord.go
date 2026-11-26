package jsonrpc

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/internal/loginaudit"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// admin.loginrecord.go
// 节点 SSH/RDP 登录历史（由 agent 上报，loginaudit 后台分析）。

func init() {
	RegisterWithGroupAndMeta("getLoginRecords", rpc.RoleAdmin, adminGetLoginRecords, &rpc.MethodMeta{
		Name:    "admin:getLoginRecords",
		Summary: "List SSH/RDP login records reported by agents",
		Params: []rpc.ParamMeta{
			{Name: "limit", Type: "string", Description: "Page size, default 50"},
			{Name: "page", Type: "string", Description: "Page number starting from 1"},
			{Name: "uuid", Type: "string", Description: "Only records of this client"},
			{Name: "untrusted_only", Type: "string", Description: "true to list only untrusted sources"},
		},
		Returns: "{ records: LoginRecord[], total: number }",
	})
	RegisterWithGroupAndMeta("clearLoginRecords", rpc.RoleAdmin, adminClearLoginRecords, &rpc.MethodMeta{
		Name:    "admin:clearLoginRecords",
		Summary: "Delete login records",
		Params: []rpc.ParamMeta{
			{Name: "uuid", Type: "string", Description: "Only delete records of this client; empty deletes all"},
		},
		Returns: "{ deleted: number }",
	})
	RegisterWithGroupAndMeta("trustLoginSource", rpc.RoleAdmin, adminTrustLoginSource, &rpc.MethodMeta{
		Name:    "admin:trustLoginSource",
		Summary: "Add a login source IP to the trusted IP allowlist",
		Params: []rpc.ParamMeta{
			{Name: "source_ip", Type: "string", Description: "IPv4 or IPv6 address to trust"},
		},
		Returns: "{ added: boolean }",
	})
}

func adminGetLoginRecords(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Limit         any    `json:"limit"`
		Page          any    `json:"page"`
		UUID          string `json:"uuid"`
		UntrustedOnly any    `json:"untrusted_only"`
	}
	req.BindParams(&params)
	limit, ok := positiveIntParam(params.Limit, 50)
	if !ok || limit > 500 {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid limit", nil)
	}
	page, ok := positiveIntParam(params.Page, 1)
	if !ok {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid page", nil)
	}
	records, total, err := loginaudit.List(loginaudit.ListOptions{
		Limit:         limit,
		Page:          page,
		ClientUUID:    strings.TrimSpace(params.UUID),
		UntrustedOnly: boolParam(params.UntrustedOnly),
	})
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to retrieve login records: "+err.Error(), nil)
	}
	configuredIPs, err := config.GetAs[string](config.LoginTrustedIPsKey)
	if err != nil {
		configuredIPs = ""
	}
	trustedNetworks, _ := loginaudit.ParseTrustedIPs(configuredIPs)
	type listedRecord struct {
		models.LoginRecord
		SourceAllowlisted bool `json:"source_allowlisted"`
	}
	listed := make([]listedRecord, 0, len(records))
	for _, record := range records {
		listed = append(listed, listedRecord{
			LoginRecord:       record,
			SourceAllowlisted: loginaudit.IsAllowlisted(net.ParseIP(record.SourceIP), trustedNetworks),
		})
	}
	return map[string]any{"records": listed, "total": total}, nil
}

func adminTrustLoginSource(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		SourceIP string `json:"source_ip"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid login source", nil)
	}
	source := net.ParseIP(strings.TrimSpace(params.SourceIP))
	if source == nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid login source IP", nil)
	}
	added, err := loginaudit.AddTrustedIP(source)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to trust login source: "+err.Error(), nil)
	}
	if added {
		actor, ip := auditActor(ctx)
		auditlog.Log(ip, actor, "Add trusted login source: "+source.String(), "info")
	}
	return map[string]any{"added": added}, nil
}

func adminClearLoginRecords(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		UUID string `json:"uuid"`
	}
	req.BindParams(&params)
	deleted, err := loginaudit.Clear(strings.TrimSpace(params.UUID))
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to delete login records: "+err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "clear login records:"+params.UUID, "warn")
	return map[string]any{"deleted": deleted}, nil
}

// positiveIntParam 接受 query string 或 JSON 数字。
func positiveIntParam(v any, def int) (int, bool) {
	switch v := v.(type) {
	case nil:
		return def, true
	case string:
		if v == "" {
			return def, true
		}
		n, err := strconv.Atoi(v)
		return n, err == nil && n > 0
	case float64:
		return int(v), v > 0 && v == float64(int(v))
	}
	return 0, false
}

func boolParam(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(v)
		return b
	}
	return false
}
