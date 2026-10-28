package jsonrpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/internal/sshmanage"
	"github.com/komari-monitor/komari/pkg/rpc"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// admin.ssh.go
// 批量管理节点 root 的 SSH 公钥、端口与 root 密码登录（由 agent 执行并校验）。

func init() {
	RegisterWithGroupAndMeta("getSSHStates", rpc.RoleAdmin, adminGetSSHStates, &rpc.MethodMeta{
		Name:    "admin:getSSHStates",
		Summary: "List the last reported SSH settings of every node",
		Returns: "{ states: { uuid, state, state_at, error, checked_at }[], remarks: { fingerprint: remark } }",
	})
	RegisterWithGroupAndMeta("setSSHKeyRemark", rpc.RoleAdmin, adminSetSSHKeyRemark, &rpc.MethodMeta{
		Name:    "admin:setSSHKeyRemark",
		Summary: "Set a panel remark for an SSH public key across all nodes",
		Params: []rpc.ParamMeta{
			{Name: "fingerprint", Type: "string", Required: true, Description: "SHA256 public key fingerprint"},
			{Name: "remark", Type: "string", Required: true, Description: "Up to 200 characters; empty restores the original key comment"},
		},
		Returns: "{ fingerprint, remark }",
	})
	RegisterWithGroupAndMeta("refreshSSHStates", rpc.RoleAdmin, adminRefreshSSHStates, &rpc.MethodMeta{
		Name:        "admin:refreshSSHStates",
		Summary:     "Read the current SSH settings from agents",
		Description: "Queries every listed agent in parallel and caches the answers. Without uuids all online agents are queried.",
		Params: []rpc.ParamMeta{
			{Name: "uuids", Type: "string[]", Description: "Target agent UUIDs; empty means all online agents"},
		},
		Returns: "{ results: { uuid, status, error, result }[] }",
	})
	RegisterWithGroupAndMeta("applySSHChanges", rpc.RoleAdmin, adminApplySSHChanges, &rpc.MethodMeta{
		Name:    "admin:applySSHChanges",
		Summary: "Add/remove root's SSH public keys, change the SSH port or toggle root password login on several agents",
		Description: "Each agent edits ~/.ssh/authorized_keys and sshd_config, restarts sshd and verifies the result on disk and on the running daemon. " +
			"Configuration edits are reverted by the agent when sshd does not come back. status is ok only when every check passed.",
		Params: []rpc.ParamMeta{
			{Name: "uuids", Type: "string[]", Required: true, Description: "Target agent UUIDs"},
			{Name: "add_keys", Type: "string[]", Description: "OpenSSH public key lines to add"},
			{Name: "remove_keys", Type: "string[]", Description: "SHA256 fingerprints of keys to remove"},
			{Name: "port", Type: "number", Description: "New SSH port; 0 keeps the current port"},
			{Name: "root_password_login", Type: "boolean", Description: "Allow or forbid root password login; omit to keep"},
			{Name: "2fa_code", Type: "string", Description: "Current 2FA code when two-factor authentication is enabled"},
		},
		Returns: "{ results: { uuid, status, error, result }[] }",
		Example: map[string]any{"uuids": []string{"agent-uuid"}, "add_keys": []string{"ssh-ed25519 AAAA... me@laptop"}, "port": 2222, "root_password_login": false},
	})
	// Installing a root key is as powerful as remote execution.
	rpc.MarkSensitive("admin:applySSHChanges")
}

func adminGetSSHStates(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	states, err := sshmanage.List()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to load SSH states: "+err.Error(), nil)
	}
	remarks, err := sshmanage.ListRemarks()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to load SSH key remarks: "+err.Error(), nil)
	}
	return map[string]any{"states": states, "remarks": remarks}, nil
}

func adminSetSSHKeyRemark(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Fingerprint string  `json:"fingerprint"`
		Remark      *string `json:"remark"`
	}
	if err := req.BindParams(&params); err != nil || params.Remark == nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "fingerprint and remark are required", nil)
	}
	fingerprint, remark, err := sshmanage.NormalizeRemark(params.Fingerprint, *params.Remark)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	if err := sshmanage.SetRemark(fingerprint, remark); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to save SSH key remark: "+err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "updated SSH key remark: "+fingerprint, "info")
	return map[string]string{"fingerprint": fingerprint, "remark": remark}, nil
}

func adminRefreshSSHStates(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		UUIDs []string `json:"uuids"`
	}
	req.BindParams(&params)
	if len(params.UUIDs) == 0 {
		params.UUIDs = agent_runtime.GetAllOnlineUUIDs()
	}
	return map[string]any{"results": sshmanage.Refresh(ctx, params.UUIDs)}, nil
}

func adminApplySSHChanges(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		UUIDs []string `json:"uuids"`
		v2.SSHChanges
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid params: "+err.Error(), nil)
	}
	if len(params.UUIDs) == 0 {
		return nil, rpc.MakeError(rpc.InvalidParams, "uuids is required", nil)
	}
	results, err := sshmanage.Apply(ctx, params.UUIDs, params.SSHChanges)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, describeSSHChanges(params.SSHChanges, results), "warn")
	return map[string]any{"results": results}, nil
}

func describeSSHChanges(ch v2.SSHChanges, results []sshmanage.Outcome) string {
	var parts []string
	if n := len(ch.AddKeys); n > 0 {
		parts = append(parts, fmt.Sprintf("add %d key(s)", n))
	}
	if len(ch.RemoveKeys) > 0 {
		parts = append(parts, "remove keys "+strings.Join(ch.RemoveKeys, ","))
	}
	if ch.Port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", ch.Port))
	}
	if ch.RootPasswordLogin != nil {
		parts = append(parts, fmt.Sprintf("root password login %v", *ch.RootPasswordLogin))
	}
	ok := 0
	for _, r := range results {
		if r.Status == sshmanage.StatusOK {
			ok++
		}
	}
	return fmt.Sprintf("ssh settings: %s on %d node(s), %d succeeded", strings.Join(parts, ", "), len(results), ok)
}
