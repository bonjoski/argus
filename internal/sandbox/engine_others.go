//go:build !darwin && !linux

package sandbox

func defaultPlatformEngine() Engine {
	return NewFallbackEngine()
}
