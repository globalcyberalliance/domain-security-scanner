# Domain Security Scanner

The Domain Security Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records. You can
also serve this functionality via an API, or a dedicated mailbox. A web application is also available if organizations
would like to perform a single domain scan for DKIM, DMARC or SPF
at [https://dmarcguide.globalcyberalliance.org](https://dmarcguide.globalcyberalliance.org).

## Download

You can download pre-compiled binaries for macOS, Linux and Windows from
the [releases](https://github.com/globalcyberalliance/domain-security-scanner/releases) page.

Alternatively, you can run the binary from within our pre-built Docker image:

```shell
docker run ghcr.io/globalcyberalliance/domain-security-scanner:latest
```

## Build

To build this application, you'll need [Go](https://golang.org/) installed.

```shell
git clone https://github.com/globalcyberalliance/domain-security-scanner.git
cd domain-security-scanner
make
```

This will output a binary called `dss`. You can then move it or use it by running `./bin/dss` (on Unix devices).

## Find a Specific Record From a Single Domain

To scan a domain for a specific type of record (A, AAAA, CNAME, DKIM, DMARC, MX, SPF, TXT), run:

`dss scan [domain] --type dmarc`

Example:

`dss scan globalcyberalliance.org --dkimSelector gca`

*Note: You may not receive your DKIM record unless you specify the `dkimSelector` flag.*

## Bulk Scan Domains

Scan any number of domains' DNS records. By default, this listens on `STDIN`, meaning you run the command via `dss scan`
and then enter each domain one-by-one.

Alternatively, you can specify multiple domains at runtime:

`dss scan globalcyberalliance.org github.com google.com`

Or you can provide [RFC 1035](https://tools.ietf.org/html/rfc1035) zone files by piping with the `-z` flag enabled:

`dss scan -z < /path/to/zonefile`

See the [zonefile.example](zonefile.example) file in this repo.

## Serve REST API

You can also expose the domain scanning functionality via a REST API. By default, this is rate limited to 3 requests per
3 second interval from a single IP address. Serve the API by running the following:

`dss serve api --port 80`

You can reach the API docs by visiting `http://server-ip:port/api/v1/docs` and the OpenAPI schema
at `http://server-ip:port/api/v1/docs.json` or `http://server-ip:port/api/v1/docs.yaml`. You can also test requests
through this interface thanks to [Scalar](https://github.com/scalar/scalar).

You can then get a single domain's results by submitting a GET request like
this `http://server-ip:port/api/v1/scan/globalcyberalliance.org`, which will return a JSON response similar to this:

```json
{
  "$schema": "http://server-ip:port/schemas/ScanSingleDomainResponseBody.json",
  "scanResult": {
    "domain": "globalcyberalliance.org",
    "bimi": "v=BIMI1;l=https://bimi.entrust.net/globalcyberalliance.org/logo.svg;a=https://bimi.entrust.net/globalcyberalliance.org/certchain.pem",
    "dkim": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrLHiExVd55zd/IQ/J/mRwSRMAocV/hMB3jXwaHH36d9NaVynQFYV8NaWi69c1veUtRzGt7yAioXqLj7Z4TeEUoOLgrKsn8YnckGs9i3B3tVFB+Ch/4mPhXWiNfNdynHWBcPcbJ8kjEQ2U8y78dHZj1YeRXXVvWob2OaKynO8/lQIDAQAB;",
    "dmarc": "v=DMARC1; p=reject; fo=1; rua=mailto:3941b663@inbox.ondmarc.com,mailto:2zw1qguv@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:2zw1qguv@fr.dmarcian.com,mailto:gca-ny-sc@globalcyberalliance.org;",
    "mx": [
      "aspmx.l.google.com.",
      "alt1.aspmx.l.google.com.",
      "alt2.aspmx.l.google.com.",
      "alt3.aspmx.l.google.com.",
      "alt4.aspmx.l.google.com."
    ],
    "spf": "v=spf1 include:_u.globalcyberalliance.org._spf.smart.ondmarc.com -all"
  },
  "advice": {
    "bimi": [
      "Your SVG logo could not be downloaded.",
      "Your VMC certificate could not be downloaded."
    ],
    "dkim": [
      "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly."
    ],
    "dmarc": [
      "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed."
    ],
    "domain": [
      "Your domain is using TLS 1.3, no further action needed!"
    ],
    "mx": [
      "All of your domains are using TLS 1.3, no further action needed!"
    ],
    "spf": [
      "SPF seems to be setup correctly! No further action needed."
    ]
  }
}
```

Alternatively, you can scan multiple domains by POSTing them to `http://server-ip:port/api/v1/scan` with a request body
like this:

```json
{
  "domains": [
    "gcatoolkit.org",
    "globalcyberalliance.org"
  ]
}
```

Which will return a JSON response like this:

```json
{
  "$schema": "http://server-ip:port/schemas/ScanMultipleDomainsResponseBody.json",
  "results": [
    {
      "scanResult": {
        "domain": "globalcyberalliance.org",
        "bimi": "v=BIMI1;l=https://bimi.entrust.net/globalcyberalliance.org/logo.svg;a=https://bimi.entrust.net/globalcyberalliance.org/certchain.pem",
        "dkim": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrLHiExVd55zd/IQ/J/mRwSRMAocV/hMB3jXwaHH36d9NaVynQFYV8NaWi69c1veUtRzGt7yAioXqLj7Z4TeEUoOLgrKsn8YnckGs9i3B3tVFB+Ch/4mPhXWiNfNdynHWBcPcbJ8kjEQ2U8y78dHZj1YeRXXVvWob2OaKynO8/lQIDAQAB;",
        "dmarc": "v=DMARC1; p=reject; fo=1; rua=mailto:3941b663@inbox.ondmarc.com,mailto:2zw1qguv@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:2zw1qguv@fr.dmarcian.com,mailto:gca-ny-sc@globalcyberalliance.org;",
        "spf": "v=spf1 include:_u.globalcyberalliance.org._spf.smart.ondmarc.com -all",
        "mx": [
          "aspmx.l.google.com.",
          "alt1.aspmx.l.google.com.",
          "alt2.aspmx.l.google.com.",
          "alt3.aspmx.l.google.com.",
          "alt4.aspmx.l.google.com."
        ]
      },
      "advice": {
        "bimi": [
          "Your SVG logo could not be downloaded.",
          "Your VMC certificate could not be downloaded."
        ],
        "dkim": [
          "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly."
        ],
        "dmarc": [
          "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed."
        ],
        "domain": [
          "Your domain is using TLS 1.3, no further action needed!"
        ],
        "mx": [
          "All of your domains are using TLS 1.3, no further action needed!"
        ],
        "spf": [
          "SPF seems to be setup correctly! No further action needed."
        ]
      }
    },
    {
      "scanResult": {
        "domain": "gcatoolkit.org",
        "dmarc": "v=DMARC1; p=reject;",
        "mx": [
          "mx01.1and1.com.",
          "mx00.1and1.com."
        ],
        "spf": "v=spf1 -all"
      },
      "advice": {
        "bimi": [
          "We couldn't detect any active BIMI record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this."
        ],
        "dkim": [
          "We couldn't detect any active DKIM record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this."
        ],
        "dmarc": [
          "You are at the highest level! However, we do recommend keeping reports enabled (via the rua tag) in case any issues may arise and you can review reports to see if DMARC is the cause."
        ],
        "domain": [
          "Your domain is using TLS 1.3, no further action needed!"
        ],
        "mx": [
          "mx01.1and1.com: Failed to reach domain",
          "mx00.1and1.com: Failed to reach domain"
        ],
        "spf": [
          "SPF seems to be setup correctly! No further action needed."
        ]
      }
    }
  ]
}
```

## Serve Dedicated Mailbox

You can also serve scan results via a dedicated mailbox. It is advised that you use this mailbox for this sole purpose,
as all emails will be deleted at each 10 second interval.

```shell
dss serve mail --inboundHost "imap.gmail.com:993" --inboundPass "SomePassword" --inboundUser "SomeAddress@domain.tld" --outboundHost "smtp.gmail.com:587" --outboundPass "SomePassword" --outboundUser "SomeAddress@domain.tld" --advise
```

You can then email this inbox from any address, and you'll receive an email back with your scan results.

### Global Flags

| Flag             | Short | Description                                                                                                     |
|------------------|-------|-----------------------------------------------------------------------------------------------------------------|
| `--advise`       | `-a`  | Provide suggestions for incorrect/missing mail security features                                                |
| `--cache`        |       | Specify how long to cache results for (default 3m)                                                              |
| `--checkTLS`     |       | Check the TLS connectivity and cert validity of domains                                                         |
| `--concurrent`   | `-c`  | The number of domains to scan concurrently (defaults to your number of CPU threads)                             |
| `--debug`        | `-d`  | Print debug logs                                                                                                |
| `--dkimSelector` |       | Specify a comma seperated list of DKIM selectors (default "")                                                   |
| `--dnsBuffer`    |       | Specify the allocated buffer for DNS responses (default 4096)                                                   |
| `--dnsProtocol`  |       | Protocol to use for DNS queries (udp, tcp, tcp-tls) (default udp)                                               |
| `--dnssec`       |       | Include scan for DNSSEC records                                                                                 |
| `--format`       | `-f`  | Format to print results in (yaml, json, csv) (default "yaml")                                                   |
| `--nameservers`  | `-n`  | Use specific nameservers, in host[:port] format; may be specified multiple times                                |
| `--outputFile`   | `-o`  | Output the results to a specified file (creates a file with the current unix timestamp if no file is specified) |
| `--prettyLog`    |       | Pretty print logs to console (default true)                                                                     |
| `--timeout`      | `-t`  | Timeout duration for a DNS query (default 15s)                                                                  |
| `--zoneFile`     | `-z`  | Input file/pipe containing an RFC 1035 zone file                                                                |

## License

This repository is licensed under the Apache License version 2.0.

Some of the project's dependencies may be under different licenses.