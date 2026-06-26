package scheduler

import (
	"context"
	"math/rand"
	"time"

	"github.com/robfig/cron/v3"
)

func ParseSpec(spec string) (cron.Schedule, error) {
	return cron.ParseStandard(spec)
}

// NextWithJitter returns the next scheduled time plus rnd()*jitter.
func NextWithJitter(s cron.Schedule, from time.Time, jitter time.Duration, rnd func() float64) time.Time {
	next := s.Next(from)
	if jitter <= 0 {
		return next
	}
	return next.Add(time.Duration(rnd() * float64(jitter)))
}

// Run blocks, invoking job at each scheduled time until ctx is cancelled.
func Run(ctx context.Context, spec string, jitter time.Duration, job func(context.Context)) error {
	s, err := ParseSpec(spec)
	if err != nil {
		return err
	}
	for {
		next := NextWithJitter(s, time.Now(), jitter, rand.Float64)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			job(ctx)
		}
	}
}
