package dns

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Run("InvalidTimeout", func(t *testing.T) {
		if _, err := New(0, 0, ""); err.Error() != "timeout must be greater than 0" {
			t.Errorf("expected: \"%s\", got: \"%s\"", "timeout must be greater than 0", err.Error())
		}
	})

	t.Run("InvalidProtocol", func(t *testing.T) {
		if _, err := New(time.Minute, 0, "protocol"); err.Error() != "invalid DNS protocol: protocol, valid options: udp, tcp, tcp-tls" {
			t.Errorf("expected: \"%s\", got: \"%s\"", "invalid DNS protocol: protocol, valid options: udp, tcp, tcp-tls", err.Error())
		}
	})

	t.Run("InvalidNameservers", func(t *testing.T) {
		if _, err := New(time.Minute, 0, "", "nameserver"); err.Error() != "failed to parse nameservers: invalid IP address: nameserver" {
			t.Errorf("expected: \"%s\", got: \"%s\"", "failed to parse nameservers: invalid IP address: nameserver", err.Error())
		}
	})
}
