package config

import "time"

// durationPtr returns a pointer to a time.Duration.
func durationPtr(t time.Duration) *time.Duration {
	return &t
}
