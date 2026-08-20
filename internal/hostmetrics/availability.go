package hostmetrics

import (
	"strings"

	"github.com/safwen511/solis-io/internal/observability"
)

// measured constructs availability metadata for a successfully measured value.
func measured(source string) observability.Availability {
	return observability.Availability{
		Available: true,
		Source:    source,
		Quality:   observability.EvidenceQualityMeasured,
	}
}

// derived builds derived from validated inputs.
func derived(source string) observability.Availability {
	return observability.Availability{
		Available: true,
		Source:    source,
		Quality:   observability.EvidenceQualityDerived,
	}
}

// unavailable constructs unavailable metadata with a bounded reason.
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

// disabled builds disabled from validated inputs.
func disabled(source string) observability.Availability {
	return unavailable(source, errDisabled)
}
