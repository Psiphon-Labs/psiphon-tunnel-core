package lib

import (
	"context"
	"errors"
	"time"
)

// registrars.go provides functionality used across different registrars

var (
	ErrRegFailed = errors.New("registration failed")
)

func SleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
