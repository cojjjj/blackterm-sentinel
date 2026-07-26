package monitor

import (
	"fmt"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func EventsFromChanges(target string, changes []model.Change) []model.Event {
	events := make([]model.Event, 0, len(changes))

	for _, ch := range changes {
		event := model.Event{
			Target:    target,
			Type:      string(ch.Type),
			Host:      ch.Host,
			Port:      ch.Port,
			Protocol:  ch.Protocol,
			Service:   ch.Service,
			CreatedAt: ch.DetectedAt,
		}

		switch ch.Type {
		case model.HostAdded:
			event.Severity = "MEDIUM"
			event.Message = fmt.Sprintf("New asset discovered: %s", ch.Host)

		case model.HostRemoved:
			event.Severity = "LOW"
			event.Message = fmt.Sprintf("Asset no longer observed: %s", ch.Host)

		case model.ServiceAdded:
			event.Severity = serviceAddedSeverity(ch)
			event.Message = fmt.Sprintf(
				"New service observed on %s: %d/%s %s",
				ch.Host,
				ch.Port,
				ch.Protocol,
				ch.Service,
			)

		case model.ServiceRemoved:
			event.Severity = "INFO"
			event.Message = fmt.Sprintf(
				"Service no longer observed on %s: %d/%s %s",
				ch.Host,
				ch.Port,
				ch.Protocol,
				ch.Service,
			)

		case model.ServiceChanged:
			event.Severity = "LOW"
			event.Message = fmt.Sprintf(
				"Service fingerprint changed on %s: %d/%s %s",
				ch.Host,
				ch.Port,
				ch.Protocol,
				ch.Service,
			)

		default:
			event.Severity = "INFO"
			event.Message = fmt.Sprintf("Network state changed on %s", ch.Host)
		}

		events = append(events, event)
	}

	return events
}

func serviceAddedSeverity(ch model.Change) string {
	switch ch.Port {
	case 21, 23, 2375:
		return "HIGH"
	case 80, 8080, 8888:
		return "MEDIUM"
	case 135, 139, 445, 3389, 5900:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
