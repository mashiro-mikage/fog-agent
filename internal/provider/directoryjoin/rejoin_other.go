//go:build !windows

package directoryjoin

import (
	"context"
	"errors"
	"os"
)

func replaceAttempt(from, to string) error { return os.Rename(from, to) }
func SetRejoinName(name string) error      { return errors.New("directory rejoin requires Windows") }
func Rebind(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	return 0, errors.New("directory rejoin requires Windows")
}
func RenameForPlan(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	return 0, errors.New("directory rename requires Windows")
}
func FindDomainController(domain string) (string, error) {
	return "", errors.New("Windows DC discovery unavailable")
}

func JoinForPlan(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	return 0, errObservationUnsupported
}
