package config

import (
	"errors"
)

var (
	ErrNoOutputConfigured = errors.New("no output configured")
)

func ValidateSensorConfig(config *Config) error {
	if config.OutputChannel == nil {
		return ErrNoOutputConfigured
	}

	return nil
}
