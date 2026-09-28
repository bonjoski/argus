//go:build linux

package sandbox

func defaultPlatformEngine() Engine {
	ll := NewLandlockEngine()
	if ll.Available() {
		return ll
	}
	return NewFallbackEngine()
}
