package sshmanage

import (
	"regexp"
	"strconv"
)

// SSH management first shipped in agent 1.5.13-fork. Snapshot builds are
// named Snapshot-YYMMDDHHMM (UTC); the feature reached main at 2610180222.
const (
	minMajor, minMinor, minPatch = 1, 5, 13
	minSnapshot                  = 2610180222
)

var (
	releaseVersion  = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)
	snapshotVersion = regexp.MustCompile(`^(?i)snapshot-(\d{10})`)
)

// agentTooOld reports whether the agent version is known to predate SSH
// management. Unknown formats (dev builds, empty) are given the benefit of
// the doubt and queried.
func agentTooOld(version string) bool {
	if m := releaseVersion.FindStringSubmatch(version); m != nil {
		v := [3]int{}
		for i := range v {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		min := [3]int{minMajor, minMinor, minPatch}
		for i := range v {
			if v[i] != min[i] {
				return v[i] < min[i]
			}
		}
		return false
	}
	if m := snapshotVersion.FindStringSubmatch(version); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n < minSnapshot
	}
	return false
}
