def phase($name; $from; $to):
  [.windows[] | select(.offset_seconds >= $from and .offset_seconds < $to)] as $windows
  | ($windows | map(.completed_requests) | add // 0) as $completed
  | {
      name: $name,
      start_offset_seconds: $from,
      end_offset_seconds: $to,
      scheduled_requests: ($windows | map(.scheduled_requests) | add // 0),
      completed_requests: $completed,
      successful_requests: ($windows | map(.successful_requests) | add // 0),
      failed_requests: ($windows | map(.failed_requests) | add // 0),
      client_saturated: ($windows | map(.client_saturated) | add // 0),
      achieved_requests_per_second: ($completed / ($to - $from)),
      latency_avg_ms: (
        if $completed > 0
        then ($windows | map(.latency_avg_ms * .completed_requests) | add) / $completed
        else 0 end
      ),
      worst_one_second_p95_ms: ($windows | map(.latency_p95_ms) | max // 0),
      worst_one_second_p99_ms: ($windows | map(.latency_p99_ms) | max // 0),
      latency_max_ms: ($windows | map(.latency_max_ms) | max // 0)
    };

[
  phase("baseline"; 0; $baseline_end),
  phase("pressure"; $baseline_end; $pressure_end),
  phase("recovery"; $pressure_end; $recovery_end)
] as $phases
| ($phases[0].latency_avg_ms) as $baseline
| {
    phases: $phases,
    comparison: {
      pressure_latency_change_percent: (
        if $baseline > 0
        then (($phases[1].latency_avg_ms - $baseline) / $baseline * 100)
        else 0 end
      ),
      recovery_latency_change_percent: (
        if $baseline > 0
        then (($phases[2].latency_avg_ms - $baseline) / $baseline * 100)
        else 0 end
      ),
      pressure_worst_one_second_p95_change_percent: (
        if $phases[0].worst_one_second_p95_ms > 0
        then (($phases[1].worst_one_second_p95_ms - $phases[0].worst_one_second_p95_ms)
              / $phases[0].worst_one_second_p95_ms * 100)
        else 0 end
      )
    }
  }
