package main

import (
	"fmt"
	"strings"
	"time"
)

func (c PluginConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(c.SyslogServer) == "" {
		return fmt.Errorf("syslog_server is required (host:port)")
	}
	switch strings.ToLower(c.SyslogProtocol) {
	case "udp", "tcp":
	default:
		return fmt.Errorf("syslog_protocol must be udp or tcp")
	}
	if c.SyslogFacility < 0 || c.SyslogFacility > 23 {
		return fmt.Errorf("syslog_facility must be between 0 and 23")
	}
	if c.SyslogSeverity < 0 || c.SyslogSeverity > 7 {
		return fmt.Errorf("syslog_severity must be between 0 and 7")
	}
	if c.SyslogHostname == "" {
		return fmt.Errorf("syslog_hostname is required")
	}
	if c.SyslogAppname == "" {
		return fmt.Errorf("syslog_appname is required")
	}
	if c.SyslogMsgID == "" {
		return fmt.Errorf("syslog_msgid is required")
	}
	if _, err := c.timeoutDuration(); err != nil {
		return err
	}
	return nil
}

func (c PluginConfig) timeoutDuration() (time.Duration, error) {
	if c.Timeout == "" {
		return 5 * time.Second, nil
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", c.Timeout, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("timeout must be greater than zero")
	}
	return d, nil
}
