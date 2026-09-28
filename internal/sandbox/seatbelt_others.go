//go:build !darwin

package sandbox

import (
	"context"
	"errors"
)

// SeatbeltEngine stub for non-macOS systems.
type SeatbeltEngine struct{}

// NewSeatbeltEngine returns a Seatbelt engine stub.
func NewSeatbeltEngine() *SeatbeltEngine {
	return &SeatbeltEngine{}
}

// Available returns false on non-macOS systems.
func (s *SeatbeltEngine) Available() bool {
	return false
}

// Name returns the descriptive name of the sandbox engine.
func (s *SeatbeltEngine) Name() string {
	return "seatbelt (unsupported on this platform)"
}

// GenerateProfile returns an unsupported error on non-macOS systems.
func (s *SeatbeltEngine) GenerateProfile(profile *Profile) (string, error) {
	return "", errors.New("seatbelt engine is only supported on macOS (darwin)")
}

// Run returns an unsupported error on non-macOS systems.
func (s *SeatbeltEngine) Run(ctx context.Context, profile *Profile, command string, args ...string) (*ExecResult, error) {
	return nil, errors.New("seatbelt engine is only supported on macOS (darwin)")
}
