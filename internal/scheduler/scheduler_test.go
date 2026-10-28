package scheduler

import (
	"testing"
	"time"
)

func TestCronScheduleUsesSystemLocalWallClock(t *testing.T) {
	originalLocal := time.Local
	time.Local = time.FixedZone("UTC+8", 8*60*60)
	t.Cleanup(func() { time.Local = originalLocal })

	schedule, err := Parse("0 0 9 * * *")
	if err != nil {
		t.Fatalf("parse schedule: %v", err)
	}
	after := time.Date(2026, 7, 17, 0, 30, 0, 0, time.UTC)
	want := time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC)
	if got := schedule.Next(after); !got.Equal(want) {
		t.Fatalf("next run = %s, want %s", got, want)
	} else if got.Location() != time.UTC {
		t.Fatalf("next run location = %s, want UTC", got.Location())
	}
}

func TestEverySchedulePreservesElapsedDuration(t *testing.T) {
	schedule, err := Parse("@every 90s")
	if err != nil {
		t.Fatalf("parse schedule: %v", err)
	}
	after := time.Now()
	if got := schedule.Next(after); got.Sub(after) != 90*time.Second {
		t.Fatalf("interval = %s, want 90s", got.Sub(after))
	}
}

func TestDailySSHRefreshUsesUTC8AcrossHostTimezones(t *testing.T) {
	originalLocal := time.Local
	t.Cleanup(func() { time.Local = originalLocal })
	for _, host := range []*time.Location{time.UTC, time.FixedZone("UTC-7", -7*3600)} {
		time.Local = host
		parsed, err := Parse("0 3 * * *")
		if err != nil {
			t.Fatal(err)
		}
		s := parsed.(cronSchedule)
		s.location = time.FixedZone("Asia/Singapore", 8*3600)
		for _, tc := range []struct{ after, want string }{
			{"2026-10-27T18:59:59Z", "2026-10-27T19:00:00Z"},
			{"2026-10-27T19:00:00Z", "2026-10-28T19:00:00Z"},
			{"2026-10-31T23:30:00Z", "2026-11-01T19:00:00Z"},
		} {
			after, _ := time.Parse(time.RFC3339, tc.after)
			want, _ := time.Parse(time.RFC3339, tc.want)
			if got := s.Next(after); !got.Equal(want) {
				t.Errorf("host %s after %s: next %s, want %s", host, after, got, want)
			}
		}
	}
}
