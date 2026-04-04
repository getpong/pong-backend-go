package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/getpong/pong-backend-go/internal/model"
)

type slackMessage struct {
	Text string `json:"text"`
}

// SendSlack posts a formatted alert message to a Slack incoming webhook URL.
func SendSlack(ctx context.Context, webhookURL string, event model.StateChangeEvent) error {
	statusEmoji := ":white_check_mark:"
	if event.NewStatus == "down" {
		statusEmoji = ":rotating_light:"
	}

	text := fmt.Sprintf(
		"%s *%s* is now *%s*\nTarget: %s\nPrevious status: %s\nMessage: %s\nChecked at: %s",
		statusEmoji,
		event.Monitor.Name,
		strings.ToUpper(event.NewStatus),
		event.Monitor.Target,
		event.OldStatus,
		event.Result.Message,
		event.Result.CheckedAt.Format("2006-01-02 15:04:05 UTC"),
	)

	payload := slackMessage{Text: text}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}
