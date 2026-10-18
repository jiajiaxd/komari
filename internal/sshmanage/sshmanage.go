// Package sshmanage reads and edits root's SSH login settings (authorized
// keys, sshd port, root password login) on many agents at once and caches
// the last reported state of each agent.
package sshmanage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	logger "github.com/komari-monitor/komari/utils/log"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
	"gorm.io/gorm/clause"
)

const concurrency = 16

// Outcome statuses of one agent in a batch.
const (
	StatusOK          = "ok"
	StatusFailed      = "failed"
	StatusOffline     = "offline"
	StatusUnsupported = "unsupported"
	StatusTimeout     = "timeout"
)

// Outcome is the result of one agent in a batch request.
type Outcome struct {
	UUID   string        `json:"uuid"`
	Status string        `json:"status"`
	Error  string        `json:"error,omitempty"`
	Result *v2.SSHResult `json:"result,omitempty"`
}

// Entry is the cached state of one agent.
type Entry struct {
	UUID      string       `json:"uuid"`
	State     *v2.SSHState `json:"state"`
	StateAt   *time.Time   `json:"state_at"`
	Error     string       `json:"error,omitempty"`
	CheckedAt time.Time    `json:"checked_at"`
}

// List returns the cached state of every agent that has been queried.
func List() ([]Entry, error) {
	var rows []models.SSHState
	if err := dbcore.GetDBInstance().Find(&rows).Error; err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(rows))
	for _, row := range rows {
		e := Entry{UUID: row.ClientUUID, StateAt: row.StateAt, Error: row.Error, CheckedAt: row.CheckedAt}
		if row.State != "" {
			var state v2.SSHState
			if err := json.Unmarshal([]byte(row.State), &state); err == nil {
				e.State = &state
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Delete removes the cached state of a deleted client.
func Delete(uuid string) error {
	return dbcore.GetDBInstance().Where("client_uuid = ?", uuid).Delete(&models.SSHState{}).Error
}

// save records an agent answer. A failed request keeps the last known state.
func save(uuid string, state *v2.SSHState, errMsg string) {
	now := time.Now().UTC()
	row := models.SSHState{ClientUUID: uuid, Error: errMsg, CheckedAt: now}
	columns := []string{"error", "checked_at"}
	if state != nil {
		data, err := json.Marshal(state)
		if err != nil {
			return
		}
		row.State = string(data)
		row.StateAt = &now
		columns = append(columns, "state", "state_at")
	}
	err := dbcore.GetDBInstance().Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "client_uuid"}},
		DoUpdates: clause.AssignmentColumns(columns),
	}).Create(&row).Error
	if err != nil {
		logger.Warn("sshmanage", "failed to save ssh state", "uuid", uuid, "error", err)
	}
}

// Refresh asks every agent for its current SSH settings.
func Refresh(ctx context.Context, uuids []string) []Outcome {
	return fanOut(ctx, uuids, v2.SSHActionGet, nil)
}

// Apply validates the changes and sends them to every agent. Agents restart
// sshd and verify the result before answering.
func Apply(ctx context.Context, uuids []string, changes v2.SSHChanges) ([]Outcome, error) {
	normalized, err := NormalizeChanges(changes)
	if err != nil {
		return nil, err
	}
	return fanOut(ctx, uuids, v2.SSHActionApply, &normalized), nil
}

// NormalizeChanges validates keys, fingerprints and the port, and rewrites
// keys to the canonical "type base64 comment" form.
func NormalizeChanges(ch v2.SSHChanges) (v2.SSHChanges, error) {
	out := v2.SSHChanges{Port: ch.Port, RootPasswordLogin: ch.RootPasswordLogin}
	seen := map[string]bool{}
	for _, line := range ch.AddKeys {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, err := ParsePublicKey(line)
		if err != nil {
			return out, fmt.Errorf("invalid public key %q: %v", abbreviate(line), err)
		}
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		out.AddKeys = append(out.AddKeys, KeyLine(k))
	}
	for _, fp := range ch.RemoveKeys {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
			return out, fmt.Errorf("invalid key fingerprint %q", fp)
		}
		out.RemoveKeys = append(out.RemoveKeys, fp)
	}
	if ch.Port < 0 || ch.Port > 65535 {
		return out, fmt.Errorf("invalid port %d", ch.Port)
	}
	if len(out.AddKeys) == 0 && len(out.RemoveKeys) == 0 && out.Port == 0 && out.RootPasswordLogin == nil {
		return out, errors.New("no changes requested")
	}
	return out, nil
}

func abbreviate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func fanOut(ctx context.Context, uuids []string, action string, changes *v2.SSHChanges) []Outcome {
	uuids = dedupe(uuids)
	outcomes := make([]Outcome, len(uuids))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, uuid := range uuids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes[i] = call(ctx, uuid, action, changes)
		}()
	}
	wg.Wait()
	return outcomes
}

func call(ctx context.Context, uuid, action string, changes *v2.SSHChanges) Outcome {
	out := Outcome{UUID: uuid}
	if !slices.Contains(agent_runtime.GetAllOnlineUUIDs(), uuid) {
		out.Status, out.Error = StatusOffline, agent_runtime.ErrSSHOffline.Error()
		return out
	}
	if !agent_runtime.IsV2Client(uuid) {
		out.Status, out.Error = StatusUnsupported, "agent does not support the v2 protocol"
		return out
	}
	result, err := agent_runtime.CallSSH(ctx, uuid, action, changes)
	switch {
	case errors.Is(err, agent_runtime.ErrSSHOffline):
		out.Status, out.Error = StatusOffline, err.Error()
		return out
	case errors.Is(err, agent_runtime.ErrSSHTimeout):
		out.Status, out.Error = StatusTimeout, err.Error()
		return out
	case err != nil:
		out.Status, out.Error = StatusFailed, err.Error()
		return out
	}
	out.Result = &result
	if result.OK {
		out.Status = StatusOK
	} else {
		out.Status, out.Error = StatusFailed, result.Error
	}
	save(uuid, result.State, result.Error)
	return out
}

func dedupe(uuids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		uuid = strings.TrimSpace(uuid)
		if uuid == "" || seen[uuid] {
			continue
		}
		seen[uuid] = true
		out = append(out, uuid)
	}
	return out
}
