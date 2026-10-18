package agent

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	v2 "github.com/komari-monitor/komari/protocol/v2"
)

const (
	// The agent only has to pick the request up within this time; running it
	// may take longer.
	sshEventTTL     = 30 * time.Second
	sshGetTimeout   = 10 * time.Second
	sshApplyTimeout = 150 * time.Second
)

var (
	ErrSSHOffline = errors.New("agent is not connected")
	ErrSSHTimeout = errors.New("agent did not answer the SSH request; the agent may need an update")
	sshMu         sync.Mutex
	sshPending    = make(map[string]sshCall)
)

type sshCall struct {
	uuid     string
	response chan v2.SSHResult
}

// CallSSH sends an SSH management request to an agent and waits for its
// answer. The caller must require administrator access.
func CallSSH(ctx context.Context, uuid, action string, changes *v2.SSHChanges) (v2.SSHResult, error) {
	timeout := sshGetTimeout
	if action == v2.SSHActionApply {
		timeout = sshApplyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !slices.Contains(GetAllOnlineUUIDs(), uuid) {
		return v2.SSHResult{}, ErrSSHOffline
	}
	requestID := newV2EventID()
	response := make(chan v2.SSHResult, 1)
	sshMu.Lock()
	sshPending[requestID] = sshCall{uuid: uuid, response: response}
	sshMu.Unlock()
	defer func() {
		sshMu.Lock()
		delete(sshPending, requestID)
		sshMu.Unlock()
	}()
	params := v2.SSHRequestParams{RequestID: requestID, Action: action, Changes: changes}
	if !DispatchV2Event(uuid, v2.MethodAgentSSH, params) {
		return v2.SSHResult{}, ErrSSHOffline
	}
	select {
	case result := <-response:
		return result, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return v2.SSHResult{}, ErrSSHTimeout
		}
		return v2.SSHResult{}, ctx.Err()
	}
}

// ResolveSSH binds the response to the authenticated agent, never to an
// agent ID supplied in the response body.
func ResolveSSH(uuid string, result v2.SSHResult) bool {
	sshMu.Lock()
	defer sshMu.Unlock()
	wait, ok := sshPending[result.RequestID]
	if !ok || wait.uuid != uuid {
		return false
	}
	delete(sshPending, result.RequestID)
	wait.response <- result
	return true
}
