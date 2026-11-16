package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"gopkg.in/yaml.v2"

	syslogclient "github.com/jhwrage/crowdsec-notification-syslog/internal/syslog"
)

var logger = hclog.New(&hclog.LoggerOptions{
	Name:       "notification-syslog",
	Level:      hclog.Info,
	Output:     os.Stderr,
	JSONFormat: true,
})

type PluginConfig struct {
	Name           string `yaml:"name"`
	LogLevel       string `yaml:"log_level"`
	SyslogServer   string `yaml:"syslog_server"`
	SyslogProtocol string `yaml:"syslog_protocol"`
	SyslogFacility int    `yaml:"syslog_facility"`
	SyslogSeverity int    `yaml:"syslog_severity"`
	SyslogHostname string `yaml:"syslog_hostname"`
	SyslogAppname  string `yaml:"syslog_appname"`
	SyslogMsgID    string `yaml:"syslog_msgid"`
	Timeout        string `yaml:"timeout"`
}

type SyslogPlugin struct {
	protobufs.UnimplementedNotifierServer
	ConfigByName map[string]PluginConfig
}

func (p *SyslogPlugin) Configure(_ context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	var cfg PluginConfig
	if err := yaml.Unmarshal(config.GetConfig(), &cfg); err != nil {
		return nil, fmt.Errorf("parse plugin configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(cfg.LogLevel))
	}
	p.ConfigByName[cfg.Name] = cfg
	logger.Info("configured syslog notification", "name", cfg.Name, "server", cfg.SyslogServer, "protocol", cfg.SyslogProtocol)
	return &protobufs.Empty{}, nil
}

func (p *SyslogPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	cfg, ok := p.ConfigByName[notification.GetName()]
	if !ok {
		return nil, fmt.Errorf("unknown syslog configuration %q", notification.GetName())
	}
	timeout, err := cfg.timeoutDuration()
	if err != nil {
		return nil, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	msg, err := syslogclient.FormatRFC5424(syslogclient.Message{
		Facility: cfg.SyslogFacility,
		Severity: cfg.SyslogSeverity,
		Hostname: cfg.SyslogHostname,
		AppName:  cfg.SyslogAppname,
		MsgID:    cfg.SyslogMsgID,
		Text:     notification.GetText(),
	})
	if err != nil {
		return nil, err
	}
	if err := syslogclient.Send(sendCtx, cfg.SyslogProtocol, cfg.SyslogServer, msg); err != nil {
		return nil, fmt.Errorf("send syslog notification: %w", err)
	}
	logger.Info("syslog notification sent", "name", cfg.Name, "server", cfg.SyslogServer, "bytes", len(msg))
	return &protobufs.Empty{}, nil
}

func main() {
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}
	impl := &SyslogPlugin{ConfigByName: make(map[string]PluginConfig)}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"syslog": &csplugin.NotifierPlugin{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
