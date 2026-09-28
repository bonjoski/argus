package mirror

import (
	"time"

	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/policy"
	"bonjoski/argus/internal/service"
)

// Config configures the Argus inline registry mirror proxy server.
type Config struct {
	Host            string
	Port            int
	UpstreamNPM     string
	UpstreamPyPI    string
	UpstreamProxies map[model.Ecosystem]string
	Threshold       int
	Strict          bool
	VettingService  *service.VettingService
	Policy          *policy.Policy
	PIDFile         string
	LogFile         string
	StateFile       string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
}

// DefaultConfig returns default configuration for the mirror proxy.
func DefaultConfig() Config {
	return Config{
		Host:         "127.0.0.1",
		Port:         8080,
		UpstreamNPM:  "https://registry.npmjs.org",
		UpstreamPyPI: "https://pypi.org",
		UpstreamProxies: map[model.Ecosystem]string{
			model.EcosystemNPM:       "https://registry.npmjs.org",
			model.EcosystemPyPI:      "https://pypi.org",
			model.EcosystemCargo:     "https://crates.io",
			model.EcosystemRubyGems:  "https://rubygems.org",
			model.EcosystemGo:        "https://proxy.golang.org",
			model.EcosystemMaven:     "https://repo.maven.apache.org/maven2",
			model.EcosystemPackagist: "https://repo.packagist.org",
		},
		Threshold:    50,
		Strict:       false,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
