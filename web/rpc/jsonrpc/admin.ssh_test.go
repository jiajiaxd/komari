package jsonrpc

import (
	"context"
	"testing"

	"github.com/komari-monitor/komari/pkg/rpc"
)

func TestSSHKeyRemarkRPC(t *testing.T) {
	const fp = "SHA256:w87qwnJxn5SJSLnQ2tED10xlaDoJLIWW8pikpUw3OpI"
	ctx := context.Background()
	set := func(params map[string]any) *rpc.JsonRpcError {
		_, err := adminSetSSHKeyRemark(ctx, &rpc.JsonRpcRequest{Params: params})
		return err
	}
	for _, params := range []map[string]any{
		{"fingerprint": fp},
		{"fingerprint": fp, "remark": nil},
		{"fingerprint": fp, "remark": 42},
		{"fingerprint": "invalid", "remark": "name"},
	} {
		if err := set(params); err == nil || err.Code != rpc.InvalidParams {
			t.Fatalf("invalid params %v: %v", params, err)
		}
	}
	for _, remark := range []string{"我的电脑", "New name", ""} {
		if err := set(map[string]any{"fingerprint": fp, "remark": remark}); err != nil {
			t.Fatal(err)
		}
		result, err := adminGetSSHStates(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		remarks := result.(map[string]any)["remarks"].(map[string]string)
		if remarks[fp] != remark {
			t.Fatalf("stored remark = %q, want %q", remarks[fp], remark)
		}
	}
}
