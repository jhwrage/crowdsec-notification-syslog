package syslog

import (
	"fmt"
	"strings"
	"time"
)

type Message struct {
	Facility int
	Severity int
	Hostname string
	AppName  string
	MsgID    string
	Text     string
}

// FormatRFC5424 formats a UTF-8 RFC 5424 message. Structured data is NILVALUE.
func FormatRFC5424(m Message) (string, error) {
	if m.Facility < 0 || m.Facility > 23 {
		return "", fmt.Errorf("facility must be between 0 and 23")
	}
	if m.Severity < 0 || m.Severity > 7 {
		return "", fmt.Errorf("severity must be between 0 and 7")
	}
	hostname, err := headerValue(m.Hostname, 255, "hostname")
	if err != nil {
		return "", err
	}
	appName, err := headerValue(m.AppName, 48, "app-name")
	if err != nil {
		return "", err
	}
	msgID, err := headerValue(m.MsgID, 32, "msgid")
	if err != nil {
		return "", err
	}

	// RFC 5424 MSG is UTF-8. Remove NUL and line terminators that can
	// otherwise confuse line-oriented collectors; retain other message text.
	text := strings.ReplaceAll(m.Text, "\x00", "")
	text = strings.ReplaceAll(text, "\r\n", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	if text == "" {
		text = "-"
	}
	pri := m.Facility*8 + m.Severity
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", pri, ts, hostname, appName, msgID, text), nil
}

func headerValue(value string, max int, field string) (string, error) {
	if value == "" || value == "-" {
		return "-", nil
	}
	if len(value) > max {
		return "", fmt.Errorf("%s exceeds RFC 5424 maximum length of %d bytes", field, max)
	}
	for _, r := range value {
		if r < 33 || r > 126 || r == ']' || r == '"' || r == '=' {
			return "", fmt.Errorf("%s contains an invalid RFC 5424 header character", field)
		}
	}
	return value, nil
}
