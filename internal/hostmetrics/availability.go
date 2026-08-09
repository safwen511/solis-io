package hostmetrics

import (
	"strings"

	"github.com/safwen511/solis-io/internal/observability"
)

func measured(source string) observability.Availability {
	return observability.Availability{
		Available: true,
		Source:    source,
		Quality:   observability.EvidenceQualityMeasured,
	}
}

func derived(source string) observability.Availability {
	return observability.Availability{
		Available: true,
		Source:    source,
		Quality:   observability.EvidenceQualityDerived,
	}
}

func unavailable(source string, err error) observability.Availability {
	detail := "unavailable"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		detail = strings.Join(strings.Fields(err.Error()), " ")
	}
	return observability.Availability{
		Source:  source,
		Quality: observability.EvidenceQualityUnavailable,
		Error:   detail,
	}
}

func disabled(source string) observability.Availability {
	return unavailable(source, errDisabled)
}
