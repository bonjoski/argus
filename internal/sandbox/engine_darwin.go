//go:build darwin

package sandbox

func defaultPlatformEngine() Engine {
	sb := NewSeatbeltEngine()
	if sb.Available() {
		return sb
	}
	return NewFallbackEngine()
}
