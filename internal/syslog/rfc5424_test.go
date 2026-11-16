package syslog

import (
	"strings"
	"testing"
)

func TestFormatRFC5424(t *testing.T) {
	got, err := FormatRFC5424(Message{
		Facility: 16, Severity: 4,
		Hostname: "edge01", AppName: "crowdsec", MsgID: "BAN",
		Text: "Blocked source 192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "<132>1 ") {
		t.Fatalf("unexpected PRI/version prefix: %q", got)
	}
	if !strings.Contains(got, " edge01 crowdsec - BAN - Blocked source") {
		t.Fatalf("unexpected RFC5424 header/message: %q", got)
	}
}

func TestFormatRejectsInvalidHeader(t *testing.T) {
	_, err := FormatRFC5424(Message{
		Facility: 1, Severity: 5,
		Hostname: "bad host", AppName: "crowdsec", MsgID: "BAN", Text: "test",
	})
	if err == nil {
		t.Fatal("expected invalid hostname to fail")
	}
}
