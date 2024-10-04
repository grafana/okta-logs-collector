package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	country_mapper "github.com/pirsquare/country-mapper"
	"github.com/sirupsen/logrus"
)

type Okta struct {
	client *okta.Client
	ctx    context.Context

	cfg           *Config
	countryMapper *country_mapper.CountryInfoClient
}

type Config struct {
	oktaURL              string
	apiKey               string
	logLevel             string
	lookbackInterval     time.Duration
	requestTimeout       time.Duration
	pollInterval         time.Duration
	sanitizeUserIdentity bool
}

// newCountryClient initializes the country mapper client.
func newCountryClient() *country_mapper.CountryInfoClient {
	client, err := country_mapper.Load()
	if err != nil {
		panic(err)
	}

	return client
}

// NewOktaClient initializes a new Okta client.
func NewOktaClient(cfg *Config) *Okta {
	ctx, client, err := okta.NewClient(context.Background(),
		okta.WithOrgUrl(cfg.oktaURL),
		okta.WithToken(cfg.apiKey),
		okta.WithRequestTimeout(int64(cfg.requestTimeout.Seconds())),
	)
	if err != nil {
		logrus.Fatalf("could not initialize okta api client: %s", err)
	}

	return &Okta{
		client:        client,
		ctx:           ctx,
		cfg:           cfg,
		countryMapper: newCountryClient(),
	}
}

// PollSystemLogs polls the Okta system logs and logs the events ti stdout using logrus.
// It polls the logs every `pollInterval`.
func (c *Okta) PollSystemLogs() error {
	since := time.Now().UTC().Add(-c.cfg.lookbackInterval).Format("2006-01-02T15:04:05.999Z")
	events, resp, err := c.client.LogEvent.GetLogs(c.ctx, &query.Params{
		Since:     since,
		SortOrder: "ASCENDING",
	})

	for {
		if err != nil {
			return err
		}

		logrus.WithField("count", len(events)).Debug("events received")

		c.printEvents(events)
		c.logRateLimits(resp)

		if !resp.HasNextPage() {
			break
		}

		logrus.Debugf("sleeping %s until next poll", c.cfg.pollInterval)
		time.Sleep(c.cfg.pollInterval)

		resp, err = resp.Next(c.ctx, &events)
	}

	return fmt.Errorf("poll ended")
}

// logRateLimits logs the rate limits from the Okta API response when
// the remaining limit is less than 2.
func (c *Okta) logRateLimits(resp *okta.Response) {
	limit, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Limit"))
	if err != nil {
		logrus.WithError(err).Error("could not parse rate limit")
		return
	}

	remaining, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Remaining"))
	if err != nil {
		logrus.WithError(err).Error("could not parse remaining rate limit")
		return
	}

	logEntry := logrus.WithFields(logrus.Fields{
		"limit":     limit,
		"remaining": remaining,
		"reset":     resp.Header.Get("X-Rate-Limit-Reset"),
	})

	// Log a warning only if we are close to the limit.
	if remaining <= 2 {
		logEntry.Warn("rate-limits")
	} else {
		logEntry.Trace("rate-limits")
	}
}

// printEvents logs the events to stdout using logrus.
func (c *Okta) printEvents(events []*okta.LogEvent) {
	for _, event := range events {
		if event.Client != nil {
			if event.Client.GeographicalContext != nil {
				country := c.countryMapper.MapByName(
					strings.TrimPrefix(event.Client.GeographicalContext.Country, "The "),
				)
				if country != nil {
					event.Client.GeographicalContext.Country = country.Alpha2
				}
			}
		}

		if c.cfg.sanitizeUserIdentity {
			sanitizeUserIdentity(event)
		}

		// We have a lookback interval defined, which means that duplicate
		// log entries could be logged; We override the log time to that of the
		// event to deduplicate entries.
		// see https://grafana.com/docs/loki/latest/architecture/#querier

		// We are using the logrus logger to log the events,
		// which means that the log entries will be sent to stdout
		// to be collected by promtail or Alloy.

		// The event severity is used to determine the log level. If the severity
		// is not a valid log level or is a debug event, we log the event as info.
		// Otherwise, we log the event with the parsed log level.
		// see https://developer.okta.com/docs/reference/api/system-log/#attributes
		if strings.ToLower(event.Severity) == "debug" {
			logrus.WithTime(*event.Published).WithField("event", &event).Info("received event")
		} else {
			level, err := logrus.ParseLevel(event.Severity)
			if err != nil {
				logrus.
					WithError(err).
					WithField("severity", event.Severity).
					Error("could not parse log level")
				logrus.
					WithTime(*event.Published).
					WithField("event", &event).
					Info("received event")
				continue
			}
			logrus.
				WithTime(*event.Published).
				WithField("event", &event).
				Log(level, "received event")
		}
	}
}

// sanitizeUserIdentity sanitizes user information in an Okta log event.
// It specifically targets the DisplayName and AlternateId fields of the Actor and Target,
// if their type is "User".
//
// Parameters:
// - event: A pointer to an okta.LogEvent object that need to be sanitized.
func sanitizeUserIdentity(event *okta.LogEvent) {
	if event.Actor != nil && event.Actor.Type == "User" {
		event.Actor.DisplayName = sanitizeString(event.Actor.DisplayName)
		event.Actor.AlternateId = sanitizeString(event.Actor.AlternateId)
	}

	for _, target := range event.Target {
		if target.Type == "User" {
			target.DisplayName = sanitizeString(target.DisplayName)
			target.AlternateId = sanitizeString(target.AlternateId)
		}
	}
}

// sanitizeString takes a string s and returns a sanitized version of it.
// It returns the first character, followed by ellipsis, and the last character.
func sanitizeString(str string) string {
	// If string is less than 3 chars, there is no reason to redact it.
	if len(str) < 3 {
		return str
	}

	return str[0:1] + "..." + str[len(str)-1:]
}
