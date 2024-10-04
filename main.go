package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/grafana/okta-logs-collector/metadata"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var config *Config

func main() {
	config = &Config{}

	app := &cli.App{
		Name:    metadata.Name,
		Usage:   "Poll Okta API for System Logs",
		Version: metadata.Version,
		Commands: []*cli.Command{
			{
				Name:   "poll",
				Usage:  "Poll Okta API for System Logs",
				Action: poll,
				Flags: []cli.Flag{
					&cli.DurationFlag{
						Name:        "lookbackInterval",
						Usage:       "Interval to rewind to when polling for updates",
						Value:       1 * time.Hour,
						Required:    false,
						EnvVars:     []string{"LOOKBACK_INTERVAL"},
						Destination: &config.lookbackInterval,
					},
					&cli.DurationFlag{
						Name:        "pollInterval",
						Usage:       "Interval between polls",
						Value:       10 * time.Second,
						Required:    false,
						EnvVars:     []string{"POLL_INTERVAL"},
						Destination: &config.pollInterval,
					},
					&cli.DurationFlag{
						Name:        "requestTimeout",
						Usage:       "Cancel requests after this interval",
						Value:       30 * time.Second,
						Required:    false,
						EnvVars:     []string{"REQUEST_TIMEOUT"},
						Destination: &config.requestTimeout,
					},
					&cli.StringFlag{
						Name:        "logLevel",
						Usage:       "Log level",
						Value:       "info",
						Required:    false,
						EnvVars:     []string{"LOG_LEVEL"},
						Destination: &config.logLevel,
					},
					&cli.BoolFlag{
						Name:        "sanitizeUserIdentity",
						Usage:       "Enable to sanitize user identity",
						Value:       false,
						EnvVars:     []string{"SANITIZE_USER_IDENTITY"},
						Destination: &config.sanitizeUserIdentity,
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "apiKey",
				Usage:       "API key used to communicate with Okta API",
				Required:    true,
				EnvVars:     []string{"API_KEY"},
				Destination: &config.apiKey,
			},
			&cli.StringFlag{
				Name:        "oktaURL",
				Usage:       "Okta URL for the organization",
				DefaultText: "https://<org>.okta.com",
				Required:    true,
				EnvVars:     []string{"OKTA_URL"},
				Destination: &config.oktaURL,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func setupLogger(output io.Writer, level string) {
	logrus.SetOutput(output)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	if level, err := logrus.ParseLevel(level); err != nil {
		logrus.SetLevel(logrus.InfoLevel)
		logrus.WithError(err).Error("failed to parse log level")
	} else {
		logrus.SetLevel(level)
	}
}

func poll(_ *cli.Context) error {
	setupLogger(os.Stdout, config.logLevel)
	client := NewOktaClient(config)
	return fmt.Errorf("failed to poll system logs: %w", client.PollSystemLogs())
}
