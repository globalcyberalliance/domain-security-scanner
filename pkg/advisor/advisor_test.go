package advisor

import (
	"reflect"
	"testing"
	"time"
)

func TestAdvisor_CheckDMARC(t *testing.T) {
	advisor := NewAdvisor(time.Second, time.Second, false)

	t.Run("Missing", func(t *testing.T) {
		expectedAdvice := []string{
			"You do not have DMARC setup!",
		}

		advice := advisor.CheckDMARC("")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("Malformed", func(t *testing.T) {
		expectedAdvice := []string{
			"Your DMARC record appears to be malformed as no semicolons seem to be present.",
		}

		advice := advisor.CheckDMARC("v=DMARC1 fo=1")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("FirstTag", func(t *testing.T) {
		expectedAdvice := "The beginning of your DMARC record should be v=DMARC1 with specific capitalization."
		advice := advisor.CheckDMARC("v=dmarc1;")

		if advice[0] != expectedAdvice {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice)
		}
	})

	t.Run("SecondTag", func(t *testing.T) {
		expectedAdvice := "The second tag in your DMARC record must be p=none/p=quarantine/p=reject."
		advice := advisor.CheckDMARC("v=DMARC1; fo=1; p=reject;")

		if advice[0] != expectedAdvice {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice)
		}
	})

	t.Run("InvalidFailureOption", func(t *testing.T) {
		expectedAdvice := "Invalid failure options specified, the record must be fo=0/fo=1/fo=d/fo=s."
		advice := advisor.CheckDMARC("v=DMARC1; p=random; fo=random;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidPercentage", func(t *testing.T) {
		expectedAdvice := "Invalid report percentage specified, it must be between 0 and 100."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; pct=101;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidPolicy", func(t *testing.T) {
		expectedAdvice := "Invalid DMARC policy specified, the record must be p=none/p=quarantine/p=reject."
		advice := advisor.CheckDMARC("v=DMARC1; p=random; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidReportIntervalType", func(t *testing.T) {
		expectedAdvice := "Invalid report interval specified, it must be a positive integer."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; ri=one;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidReportIntervalValue", func(t *testing.T) {
		expectedAdvice := "Invalid report interval specified, it must be a positive value."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; ri=-1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidRUADestinationAddress", func(t *testing.T) {
		expectedAdvice := "Invalid aggregate report destination specified, it should be a valid email address."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; rua=mailto:dest")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidRUADestinationFormat", func(t *testing.T) {
		expectedAdvice := "Invalid aggregate report destination specified, it should begin with mailto:."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; rua=dest@domain.tld")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidRUFDestinationAddress", func(t *testing.T) {
		expectedAdvice := "Invalid forensic report destination specified, it should be a valid email address."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; ruf=mailto:dest")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidRUFDestinationFormat", func(t *testing.T) {
		expectedAdvice := "Invalid forensic report destination specified, it should begin with mailto:."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; ruf=dest@domain.tld")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("InvalidSubdomainPolicy", func(t *testing.T) {
		expectedAdvice := "Invalid subdomain policy specified, the record must be sp=none/sp=quarantine/sp=reject."
		advice := advisor.CheckDMARC("v=DMARC1; sp=random; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("MissingSubdomainPolicy", func(t *testing.T) {
		expectedAdvice := "Subdomain policy isn't specified, they'll default to the main policy instead."
		advice := advisor.CheckDMARC("v=DMARC1; p=reject; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice[0])
		}
	})
}

func TestAdvisor_CheckSPF(t *testing.T) {
	advisor := NewAdvisor(time.Second, time.Second, false)

	t.Run("Missing", func(t *testing.T) {
		expectedAdvice := []string{"We couldn't detect any active SPF record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this."}
		advice := advisor.CheckSPF("")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("PlusAll", func(t *testing.T) {
		expectedAdvice := []string{"Your SPF record contains the +all tag. It is strongly recommended that this be changed to either -all or ~all. The +all tag allows for any system regardless of SPF to send mail on the organization’s behalf."}
		advice := advisor.CheckSPF("v=spf1 +all")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("MissingAll", func(t *testing.T) {
		expectedAdvice := []string{"Your SPF record is missing the all tag. Please visit https://dmarcguide.globalcyberalliance.org to fix this."}
		advice := advisor.CheckSPF("v=spf1 include:_spf.google.com")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("SoftFail", func(t *testing.T) {
		expectedAdvice := []string{"SPF seems to be setup correctly, but it's recommended that you change from SoftFail to HardFail"}
		advice := advisor.CheckSPF("v=spf1 include:_spf.rexx-suite.com ~all")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("HardFail", func(t *testing.T) {
		expectedAdvice := []string{"SPF seems to be setup correctly! No further action needed."}
		advice := advisor.CheckSPF("v=spf1 include:_spf.rexx-suite.com -all")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})
}
