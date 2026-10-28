package sshmanage

import (
	"context"
	"time"

	"github.com/komari-monitor/komari/internal/scheduler"
	logger "github.com/komari-monitor/komari/utils/log"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// RegisterDailyRefresh runs on the server even when no admin page is open.
func RegisterDailyRefresh() error {
	// Singapore uses UTC+8 year-round. Keep the schedule independent of the
	// host/container timezone and of the availability of system tzdata.
	return scheduler.AddContextFuncInLocation("ssh:refresh", "0 3 * * *",
		time.FixedZone("Asia/Singapore", 8*60*60), false, refreshOnline)
}

func refreshOnline(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	results := Refresh(ctx, agent_runtime.GetAllOnlineUUIDs())
	ok := 0
	for _, result := range results {
		if result.Status == StatusOK {
			ok++
		}
	}
	logger.Infof("sshmanage", "Daily SSH refresh: %d/%d nodes succeeded", ok, len(results))
}
