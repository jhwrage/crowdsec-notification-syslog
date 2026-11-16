package syslog

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Send sends one RFC 5424 message. TCP uses RFC 6587 octet-counting framing.
func Send(ctx context.Context, protocol, address, message string) error {
	protocol = strings.ToLower(protocol)
	if protocol != "udp" && protocol != "tcp" {
		return fmt.Errorf("unsupported syslog protocol %q", protocol)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return fmt.Errorf("syslog_server must be host:port: %w", err)
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, protocol, address)
	if err != nil {
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	payload := []byte(message)
	if protocol == "tcp" {
		payload = []byte(strconv.Itoa(len(payload)) + " " + message)
	}
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("connection closed while writing syslog message")
		}
		payload = payload[n:]
	}
	return nil
}
