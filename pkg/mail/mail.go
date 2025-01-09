package mail

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/emersion/go-imap"
	imapClient "github.com/emersion/go-imap/client"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/spf13/cast"
	"github.com/wneessen/go-mail"
)

type (
	Config struct {
		Inbound struct {
			Host string `json:"host"`
			Pass string `json:"pass"`
			User string `json:"user"`
		} `json:"inbound"`
		Outbound struct {
			Host string `json:"host"`
			Pass string `json:"pass"`
			User string `json:"user"`
		} `json:"outbound"`
	}

	FoundMail struct {
		Address      string
		DKIMSelector string
	}
)

// GetMail returns the most recent mail found within the logged-in user's mailbox.
func (s *Server) GetMail() (map[string]FoundMail, error) {
	client, err := s.Login()
	if err != nil {
		return nil, err
	}
	defer client.Logout()

	mailbox, err := client.Select("INBOX", false)
	if err != nil {
		return nil, err
	}

	// check for new emails
	from := uint32(1)
	to := mailbox.Messages
	if mailbox.Messages == 0 {
		return nil, errors.New("no new messages")
	}

	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- client.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, "BODY[HEADER]"}, messages)
	}()

	addresses := make(map[string]FoundMail)
	var emailsToBeDeleted []uint32
	for msg := range messages {
		// DKIM
		headerSection, _ := imap.ParseBodySectionName("RFC822.HEADER")
		header := msg.GetBody(headerSection)
		headerScanner := bufio.NewScanner(header)
		var dkimDone, dkimFound bool
		var dkim string
		for headerScanner.Scan() {
			if dkimFound {
				if headerScanner.Text() != strings.TrimSpace(headerScanner.Text()) {
					dkim += headerScanner.Text()
				} else {
					dkimDone = true
					dkimFound = false
				}
			}
			if !dkimDone {
				if strings.Contains(headerScanner.Text(), "DKIM-Signature") {
					dkimFound = true
					dkim += strings.Trim(headerScanner.Text(), "DKIM-Signature:")
				}
			}
		}

		if dkimDone {
			dkim = strings.ReplaceAll(dkim, " ", "")
			dkim = strings.ReplaceAll(dkim, ";", "; ")
		}

		if len(msg.Envelope.From) == 0 {
			continue
		}

		if dkim != "" {
			dkimHeaders := strings.Split(dkim, ";")
			for _, dkimHeader := range dkimHeaders {
				if strings.HasPrefix(dkimHeader, " s=") {
					dkim = strings.TrimPrefix(dkimHeader, " s=")
					break
				}
			}
		}

		addresses[msg.Envelope.From[0].HostName] = FoundMail{
			Address:      msg.Envelope.From[0].Address(),
			DKIMSelector: dkim,
		}
		emailsToBeDeleted = append(emailsToBeDeleted, msg.SeqNum)
	}

	if err = <-done; err != nil {
		return nil, err
	}

	// Mark messages as deleted
	flags := []interface{}{imap.DeletedFlag}
	item := imap.FormatFlagsOp(imap.AddFlags, true)
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(emailsToBeDeleted...)

	if err = client.Store(seqSet, item, flags, nil); err != nil {
		return nil, err
	}

	// Permanently delete all marked emails
	if err = client.Expunge(nil); err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, errors.New("no valid messages")
	}

	return addresses, nil
}

// Login initializes an open session to the configured IMAP server.
func (s *Server) Login() (*imapClient.Client, error) {
	client, err := imapClient.DialTLS(s.config.Inbound.Host, nil)
	if err != nil {
		return nil, err
	}

	if err = client.Login(s.config.Inbound.User, s.config.Inbound.Pass); err != nil {
		return nil, err
	}

	return client, nil
}

// SendMail takes a hermes.Email object, converts it into both html and plaintext,
// and then send the email to the provided mailbox.
func (s *Server) SendMail(mailbox string, result model.ScanResultWithAdvice) error {
	html, plaintext, err := s.getMailContents(result)
	if err != nil {
		return err
	}

	m := mail.NewMsg()
	m.Subject("Email Security Scan Results")

	if err = m.From(s.config.Outbound.User); err != nil {
		return fmt.Errorf("failed to set From address: %w", err)
	}

	if err = m.To(mailbox); err != nil {
		return fmt.Errorf("failed to set To address: %w", err)
	}

	m.SetBodyString(mail.TypeTextPlain, plaintext)
	m.SetBodyString(mail.TypeTextHTML, html)

	host, port, err := net.SplitHostPort(s.config.Outbound.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port: %w", err)
	}

	client, err := mail.NewClient(host, mail.WithPort(cast.ToInt(port)), mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(s.config.Outbound.User), mail.WithPassword(s.config.Outbound.Pass))
	if err != nil {
		return fmt.Errorf("failed to create mail client: %w", err)
	}

	if err = client.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}

	return nil
}

func stringify(array []string) (result string) {
	if len(array) > 0 {
		for _, s := range array {
			if len(result) == 0 {
				result = s
			} else {
				result = result + "\n" + s
			}
		}
	}

	return result
}
