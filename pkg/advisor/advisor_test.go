package advisor

import (
	"testing"
	"time"
)

func TestAdvisor_CheckDMARC(t *testing.T) {
	advisor := NewAdvisor(time.Second, time.Second, false)

	testDMARC := func(expectedAdvice string, record string) {
		advice := advisor.CheckDMARC(record)
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("advice: \"%s\", expected: \"%s\"", advice, expectedAdvice)
		}
	}

	t.Run("Missing", func(t *testing.T) {
		testDMARC(
			"You do not have DMARC setup!",
			"",
		)
	})

	t.Run("Malformed", func(t *testing.T) {
		testDMARC(
			"Your DMARC record appears to be malformed as no semicolons seem to be present.",
			"v=DMARC1 fo=1",
		)
	})

	t.Run("FirstTag", func(t *testing.T) {
		testDMARC(
			"The beginning of your DMARC record should be v=DMARC1 with specific capitalization.",
			"v=dmarc1;",
		)
	})

	t.Run("SecondTag", func(t *testing.T) {
		testDMARC(
			"The second tag in your DMARC record must be p=none/p=quarantine/p=reject.",
			"v=DMARC1; fo=1; p=reject;",
		)
	})

	t.Run("InvalidADKIMValue", func(t *testing.T) {
		testDMARC(
			"The adkim value is invalid, it must be 'r' or 's'.",
			"v=DMARC1; p=none; fo=1; pct=101; adkim=t;",
		)
	})

	t.Run("InvalidASPFValue", func(t *testing.T) {
		testDMARC(
			"The aspf value is invalid, it must be 'r' or 's'.",
			"v=DMARC1; p=none; fo=1; pct=101; aspf=t;",
		)
	})

	t.Run("InvalidFailureOption", func(t *testing.T) {
		testDMARC(
			"Invalid failure options specified, the record must be fo=0/fo=1/fo=d/fo=s.",
			"v=DMARC1; p=random; fo=random;",
		)
	})

	t.Run("InvalidPercentage", func(t *testing.T) {
		testDMARC(
			"Invalid report percentage specified, it must be between 0 and 100.",
			"v=DMARC1; p=none; fo=1; pct=101;",
		)
	})

	t.Run("InvalidPolicy", func(t *testing.T) {
		testDMARC(
			"Invalid DMARC policy specified, the record must be p=none/p=quarantine/p=reject.",
			"v=DMARC1; p=random; fo=1;",
		)
	})

	t.Run("InvalidReportIntervalType", func(t *testing.T) {
		testDMARC(
			"Invalid report interval specified, it must be a positive integer.",
			"v=DMARC1; p=none; ri=one;",
		)
	})

	t.Run("InvalidReportIntervalValue", func(t *testing.T) {
		testDMARC(
			"Invalid report interval specified, it must be a positive value.",
			"v=DMARC1; p=none; ri=-1;",
		)
	})

	t.Run("InvalidRUADestinationAddress", func(t *testing.T) {
		testDMARC(
			"Invalid aggregate report destination specified, it should be a valid email address.",
			"v=DMARC1; p=none; fo=1; rua=mailto:dest",
		)
	})

	t.Run("InvalidRUADestinationFormat", func(t *testing.T) {
		testDMARC(
			"Invalid aggregate report destination specified, it should begin with mailto:.",
			"v=DMARC1; p=none; fo=1; rua=dest@domain.tld",
		)
	})

	t.Run("InvalidRUFDestinationAddress", func(t *testing.T) {
		testDMARC(
			"Invalid forensic report destination specified, it should be a valid email address.",
			"v=DMARC1; p=none; fo=1; ruf=mailto:dest",
		)
	})

	t.Run("InvalidRUFDestinationFormat", func(t *testing.T) {
		testDMARC(
			"Invalid forensic report destination specified, it should begin with mailto:.",
			"v=DMARC1; p=none; fo=1; ruf=dest@domain.tld",
		)
	})

	t.Run("InvalidSubdomainPolicy", func(t *testing.T) {
		testDMARC(
			"Invalid subdomain policy specified, the record must be sp=none/sp=quarantine/sp=reject.",
			"v=DMARC1; sp=random; fo=1;",
		)
	})

	t.Run("MissingPolicy", func(t *testing.T) {
		testDMARC(
			"No DMARC policy found, record must contain p=none/p=quarantine/p=reject.",
			"fo=1;",
		)
	})

	t.Run("MissingSubdomainPolicy", func(t *testing.T) {
		testDMARC(
			"Subdomain policy isn't specified, they'll default to the main policy instead.",
			"v=DMARC1; p=reject; fo=1;",
		)
	})

	t.Run("MissingVersion", func(t *testing.T) {
		testDMARC(
			"The first tag in your DMARC record should be v=DMARC1.",
			"p=reject;",
		)
	})

	t.Run("PolicyQuarantineWithRUA", func(t *testing.T) {
		testDMARC(
			"You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed.",
			"v=DMARC1; p=quarantine; rua=dest@domain.tld",
		)
	})

	t.Run("PolicyQuarantineWithoutRUA", func(t *testing.T) {
		testDMARC(
			"You are at the highest level! However, we do recommend keeping reports enabled (via the rua tag) in case any issues may arise and you can review reports to see if DMARC is the cause.",
			"v=DMARC1; p=quarantine",
		)
	})

	t.Run("PolicyRejectWithRUA", func(t *testing.T) {
		testDMARC(
			"You are currently at the second level and receiving reports. Please make sure to review the reports, make the appropriate adjustments, and move to reject soon.",
			"v=DMARC1; p=reject; rua=dest@domain.tld",
		)
	})

	t.Run("PolicyQuarantineWithoutRUA", func(t *testing.T) {
		testDMARC(
			"You are currently at the second level. However, you must receive reports in order to determine if DKIM/DMARC/SPF are functioning correctly and move to the highest level (reject). Please add the ‘rua’ tag to your DMARC policy.",
			"v=DMARC1; p=reject",
		)
	})

	t.Run("UnknownTag", func(t *testing.T) {
		testDMARC(
			"Unexpected tag in record: invalidtag.",
			"v=DMARC1; invalidtag=value",
		)
	})
}

func TestAdvisor_CheckSPF(t *testing.T) {
	advisor := NewAdvisor(time.Second, time.Second, false)

	testSPF := func(expectedAdvice string, record string) {
		advice := advisor.CheckSPF(record)
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("advice: \"%s\", expected: \"%s\"", advice, expectedAdvice)
		}
	}

	t.Run("Missing", func(t *testing.T) {
		testSPF(
			"We couldn't detect any active SPF record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this.",
			"",
		)
	})

	t.Run("Valid", func(t *testing.T) {
		testSPF(
			"SPF seems to be setup correctly! No further action needed.",
			"v=spf1 include:_u.globalcyberalliance.org._spf.smart.ondmarc.com include:_spf.google.com -all",
		)
	})
}
