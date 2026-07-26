package notify

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func Notify(title, message string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	title = xmlEscape(strings.TrimSpace(title))
	message = xmlEscape(strings.TrimSpace(message))

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml(@"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>%s</text>
      <text>%s</text>
    </binding>
  </visual>
</toast>
"@)

$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('BLACKTERM Sentinel')
$notifier.Show($toast)
`, title, message)

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy",
		"Bypass",
		"-Command",
		script,
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("show Windows notification: %w", err)
	}
	return nil
}

func ShouldNotify(event model.Event, minimum string) bool {
	eventRank := SeverityRank(event.Severity)
	minRank := SeverityRank(minimum)

	return eventRank != 99 && minRank != 99 && eventRank <= minRank
}

func SeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 99
	}
}

func ValidMinimum(value string) bool {
	return SeverityRank(value) != 99
}

func EventTitle(event model.Event) string {
	return fmt.Sprintf("Sentinel %s", strings.ToUpper(event.Severity))
}

func EventMessage(event model.Event) string {
	if strings.TrimSpace(event.Message) != "" {
		return event.Message
	}
	if event.Host != "" {
		return fmt.Sprintf("%s on %s", event.Type, event.Host)
	}
	return event.Type
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}
