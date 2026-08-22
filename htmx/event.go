package htmx

import (
	"fmt"
	"strings"
)

// EventTypes are represented as integer constants to avoid typos but are converted to
// strings for use in HTMX headers.
type EventType uint8

const (
	EventUnknown EventType = iota
	EventCreated
	EventUpdated
	EventDeleted
)

func (e EventType) String() string {
	switch e {
	case EventCreated:
		return "created"
	case EventUpdated:
		return "updated"
	case EventDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

type Event struct {
	Type EventType
	Name string
}

func (e Event) String() string {
	return strings.ToLower(fmt.Sprintf("%s-%s", e.Name, e.Type))
}

var (
	_ fmt.Stringer = (*Event)(nil)
	_ fmt.Stringer = EventType(0)
)
