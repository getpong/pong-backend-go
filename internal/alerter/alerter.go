package alerter

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

// Alerter consumes state change events and dispatches notifications
// to the appropriate alert contacts.
type Alerter struct {
	store   *store.Store
	alertCh chan model.StateChangeEvent
	cfg     *config.Config
	done    chan struct{}
}

// NewAlerter creates a new Alerter.
func NewAlerter(s *store.Store, alertCh chan model.StateChangeEvent, cfg *config.Config) *Alerter {
	return &Alerter{
		store:   s,
		alertCh: alertCh,
		cfg:     cfg,
		done:    make(chan struct{}),
	}
}

// Start begins consuming events from the alert channel. It blocks until ctx is cancelled.
func (a *Alerter) Start(ctx context.Context) {
	slog.Info("alerter started")
	defer close(a.done)

	for {
		select {
		case <-ctx.Done():
			slog.Info("alerter stopping: context cancelled")
			return
		case event, ok := <-a.alertCh:
			if !ok {
				slog.Info("alerter stopping: channel closed")
				return
			}
			a.handleEvent(ctx, event)
		}
	}
}

// Done returns a channel that is closed when the alerter has fully stopped.
func (a *Alerter) Done() <-chan struct{} {
	return a.done
}

func (a *Alerter) handleEvent(ctx context.Context, event model.StateChangeEvent) {
	contacts, err := a.store.GetAlertContactsForMonitor(ctx, event.Monitor.ID)
	if err != nil {
		slog.Error("failed to get alert contacts",
			"monitor_id", event.Monitor.ID,
			"error", err,
		)
		return
	}

	if len(contacts) == 0 {
		slog.Debug("no alert contacts for monitor", "monitor_id", event.Monitor.ID)
		return
	}

	message := fmt.Sprintf("Monitor %q (%s) changed from %s to %s: %s",
		event.Monitor.Name,
		event.Monitor.Target,
		event.OldStatus,
		event.NewStatus,
		event.Result.Message,
	)

	for _, contact := range contacts {
		var sendErr error

		switch contact.Type {
		case "email":
			if !contact.Verified {
				slog.Debug("skipping unverified email contact", "contact_id", contact.ID)
				continue
			}
			sendErr = SendEmail(a.cfg, contact.Value, event)
		case "slack":
			sendErr = SendSlack(ctx, contact.Value, event)
		case "webhook":
			sendErr = SendWebhook(ctx, contact.Value, event)
		default:
			slog.Warn("unknown alert contact type",
				"type", contact.Type,
				"contact_id", contact.ID,
			)
			continue
		}

		if sendErr != nil {
			slog.Error("failed to send alert",
				"type", contact.Type,
				"contact_id", contact.ID,
				"monitor_id", event.Monitor.ID,
				"error", sendErr,
			)
		} else {
			slog.Info("alert sent",
				"type", contact.Type,
				"contact_id", contact.ID,
				"monitor_id", event.Monitor.ID,
			)
		}

		alertLog := &model.AlertLog{
			MonitorID:      event.Monitor.ID,
			AlertContactID: contact.ID,
			Type:           event.NewStatus,
			Message:        message,
			SentAt:         time.Now(),
		}
		if err := a.store.InsertAlertLog(ctx, alertLog); err != nil {
			slog.Error("failed to insert alert log",
				"monitor_id", event.Monitor.ID,
				"contact_id", contact.ID,
				"error", err,
			)
		}
	}
}
