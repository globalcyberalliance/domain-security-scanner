package scanner

import (
	"runtime"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOptionOverwrite(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("ValidOverwrite", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithCacheDuration(0))
		require.NoError(t, err)

		err = scanner.OverwriteOption(WithCacheDuration(time.Second * 10))
		require.NoError(t, err)
	})

	t.Run("InvalidOverwrite", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithCacheDuration(0))
		require.NoError(t, err)

		err = scanner.OverwriteOption(nil)
		require.ErrorContains(t, err, "invalid option")
	})
}

func TestOptionWithCacheDuration(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("ValidCacheDuration", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithCacheDuration(time.Second*10))
		require.NoError(t, err)
		require.Equal(t, time.Second*10, scanner.cacheDuration)
	})

	t.Run("ZeroCacheDuration", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithCacheDuration(0))
		require.NoError(t, err)
		require.Equal(t, time.Duration(0), scanner.cacheDuration)
	})
}

func TestOptionWithConcurrentScans(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("ValidConcurrentScans", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithConcurrentScans(5))
		require.NoError(t, err)
		require.Equal(t, uint16(5), scanner.poolSize)
	})

	t.Run("ZeroConcurrentScans", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithConcurrentScans(0))
		require.NoError(t, err)
		require.Equal(t, uint16(runtime.NumCPU()), scanner.poolSize)
	})
}

func TestOptionWithDKIMSelectors(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("ValidDKIMSelectors", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDKIMSelectors("selector1", "selector1._google"))
		require.NoError(t, err)
		require.Equal(t, []string{"selector1", "selector1._google"}, scanner.dnsClient.DKIMSelectors)
	})

	t.Run("InvalidDKIMSelectorEndingCharacter", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors("selector1."))
		require.ErrorContains(t, err, "should not end with '.'")
	})

	t.Run("InvalidDKIMSelectorStartingCharacter", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors(".selector1"))
		require.ErrorContains(t, err, "should not start with '.'")
	})

	t.Run("InvalidDKIMSelectorCharacter", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors("selector1@"))
		require.ErrorContains(t, err, "DKIM selector has invalid character '@'")
	})

	t.Run("InvalidDKIMSelectorLength", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors("an_unnecessarily_long_and_invalid_dkim_selector_that_is_64_chars"))
		require.ErrorContains(t, err, "can't exceed 63")
	})

	t.Run("EmptyDKIMSelector", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors(""))
		require.ErrorContains(t, err, "DKIM selector is empty")
	})

	t.Run("NilDKIMSelectors", func(t *testing.T) {
		_, err := New(logger, timeout, WithDKIMSelectors())
		require.ErrorContains(t, err, "no DKIM selectors provided")
	})
}

func TestOptionWithDNSBuffer(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("BufferWithinLimit", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSBuffer(2048))
		require.NoError(t, err)
		require.Equal(t, uint16(2048), scanner.dnsClient.Buffer)
	})

	t.Run("BufferExceedsLimit", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSBuffer(5000))
		require.NoError(t, err)
		require.Equal(t, uint16(5000), scanner.dnsClient.Buffer)
	})

	t.Run("BufferAtLimit", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSBuffer(4096))
		require.NoError(t, err)
		require.Equal(t, uint16(4096), scanner.dnsClient.Buffer)
	})
}

func TestOptionWithDNSProtocol(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("InvalidProtocol", func(t *testing.T) {
		_, err := New(logger, timeout, WithDNSProtocol("invalid_protocol"))
		require.Error(t, err)
	})

	t.Run("ValidProtocolTCP", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSProtocol("TCP"))
		require.NoError(t, err)
		require.Equal(t, "tcp", scanner.dnsClient.Protocol)
	})

	t.Run("ValidProtocolTCPWithTLS", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSProtocol("TCP-tls"))
		require.NoError(t, err)
		require.Equal(t, "tcp-tls", scanner.dnsClient.Protocol)
	})

	t.Run("ValidProtocolUDP", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithDNSProtocol("UDP"))
		require.NoError(t, err)
		require.Equal(t, "udp", scanner.dnsClient.Protocol)
	})
}

func TestOptionWithNameservers(t *testing.T) {
	logger := zerolog.Nop()
	timeout := time.Second * 5

	t.Run("EmptyNameservers", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithNameservers(nil))
		require.NoError(t, err)
		require.NotEmpty(t, scanner.dnsClient.Nameservers)
	})

	t.Run("InvalidNameservers", func(t *testing.T) {
		_, err := New(logger, timeout, WithNameservers([]string{"invalid_nameserver"}))
		require.ErrorContains(t, err, "invalid IP address")
	})

	t.Run("ValidNameserverWithPort", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithNameservers([]string{"8.8.8.8:53"}))
		require.NoError(t, err)
		require.Equal(t, []string{"8.8.8.8:53"}, scanner.dnsClient.Nameservers)
	})

	t.Run("ValidNameserverWithoutPort", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithNameservers([]string{"8.8.8.8"}))
		require.NoError(t, err)
		require.Equal(t, []string{"8.8.8.8:53"}, scanner.dnsClient.Nameservers)
	})

	t.Run("ValidNameserverWithPortV6", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithNameservers([]string{"[2001:4860:4860::8888]:53"}))
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, scanner.dnsClient.Nameservers)
	})

	t.Run("ValidNameserverWithoutPortV6", func(t *testing.T) {
		scanner, err := New(logger, timeout, WithNameservers([]string{"2001:4860:4860::8888"}))
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, scanner.dnsClient.Nameservers)
	})
}
