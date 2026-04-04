package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/getpong/pong-backend-go/internal/model"
)

type webhookPayload struct {
	MonitorName   string `json:"monitor_name"`
	MonitorTarget string `json:"monitor_target"`
	Status        string `json:"status"`
	OldStatus     string `json:"old_status"`
	Message       string `json:"message"`
	CheckedAt     string `json:"checked_at"`
}

// SendWebhook sends a JSON POST request to the given URL with event details.
func SendWebhook(ctx context.Context, url string, event model.StateChangeEvent) error {
	payload := webhookPayload{
		MonitorName:   event.Monitor.Name,
		MonitorTarget: event.Monitor.Target,
		Status:        event.NewStatus,
		OldStatus:     event.OldStatus,
		Message:       event.Result.Message,
		CheckedAt:     event.Result.CheckedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pong-backend-go/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
