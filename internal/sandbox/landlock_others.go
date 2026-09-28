//go:build !linux

package sandbox

import (
	"context"
	"errors"
)

// LandlockEngine stub for non-Linux platforms.
type LandlockEngine struct{}

// NewLandlockEngine returns a Landlock engine stub.
func NewLandlockEngine() *LandlockEngine {
	return &LandlockEngine{}
}

// Available returns false on non-Linux platforms.
func (l *LandlockEngine) Available() bool {
	return false
}

// Name returns the descriptive name of the sandbox engine.
func (l *LandlockEngine) Name() string {
	return "landlock (unsupported on this platform)"
}

// GenerateProfile returns an unsupported error on non-Linux platforms.
func (l *LandlockEngine) GenerateProfile(profile *Profile) (string, error) {
	return "", errors.New("landlock engine is only supported on Linux")
}

// Run returns an unsupported error on non-Linux platforms.
func (l *LandlockEngine) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	return nil, errors.New("landlock engine is only supported on Linux")
}
