package alerter

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/model"
)

// SendEmail sends an alert email using SMTP with PlainAuth.
func SendEmail(cfg *config.Config, to string, event model.StateChangeEvent) error {
	subject := fmt.Sprintf("[Pong Monitor] %s is %s", event.Monitor.Name, strings.ToUpper(event.NewStatus))

	body := fmt.Sprintf(
		"Monitor: %s\nTarget: %s\nStatus: %s -> %s\nMessage: %s\nChecked at: %s",
		event.Monitor.Name,
		event.Monitor.Target,
		event.OldStatus,
		event.NewStatus,
		event.Result.Message,
		event.Result.CheckedAt.Format("2006-01-02 15:04:05 UTC"),
	)

	msg := fmt.Sprintf(
		"From: Pong <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		cfg.SMTPFrom,
		to,
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%s", cfg.SMTPHost, cfg.SMTPPort)

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	if err := smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("send email to %s: %w", to, err)
	}

	return nil
}
