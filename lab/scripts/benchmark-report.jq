# average returns null for an empty sample instead of fabricating a mean.
def average:
  if length > 0 then add / length else null end;

# median computes the middle order statistic, averaging the two center values.
def median:
  if length == 0 then null
  else
    sort as $sorted
    | ($sorted | length) as $count
    | if ($count % 2) == 1
      then $sorted[($count / 2 | floor)]
      else (($sorted[$count / 2 - 1] + $sorted[$count / 2]) / 2)
      end
  end;

# sample_stddev estimates sample variation and requires at least two observations.
def sample_stddev:
  if length < 2 then null
  else
    . as $values
    | ($values | average) as $mean
    | ($values
       | map((. - $mean) * (. - $mean))
       | add / (length - 1)
       | sqrt)
  end;

# distribution summarizes one numeric sample without applying pass/fail policy.
def distribution:
  {
    count: length,
    mean: average,
    median: median,
    min: (if length > 0 then min else null end),
    max: (if length > 0 then max else null end),
    sample_stddev: sample_stddev
  };

# t95 returns the two-sided 95% Student-t critical value for the sample size.
def t95($degrees_of_freedom):
  if $degrees_of_freedom <= 1 then 12.706
  elif $degrees_of_freedom == 2 then 4.303
  elif $degrees_of_freedom == 3 then 3.182
  elif $degrees_of_freedom == 4 then 2.776
  elif $degrees_of_freedom == 5 then 2.571
  elif $degrees_of_freedom == 6 then 2.447
  elif $degrees_of_freedom == 7 then 2.365
  elif $degrees_of_freedom == 8 then 2.306
  elif $degrees_of_freedom == 9 then 2.262
  elif $degrees_of_freedom == 10 then 2.228
  elif $degrees_of_freedom == 11 then 2.201
  elif $degrees_of_freedom == 12 then 2.179
  elif $degrees_of_freedom == 13 then 2.160
  elif $degrees_of_freedom == 14 then 2.145
  elif $degrees_of_freedom == 15 then 2.131
  elif $degrees_of_freedom == 16 then 2.120
  elif $degrees_of_freedom == 17 then 2.110
  elif $degrees_of_freedom == 18 then 2.101
  elif $degrees_of_freedom == 19 then 2.093
  elif $degrees_of_freedom == 20 then 2.086
  elif $degrees_of_freedom == 21 then 2.080
  elif $degrees_of_freedom == 22 then 2.074
  elif $degrees_of_freedom == 23 then 2.069
  elif $degrees_of_freedom == 24 then 2.064
  elif $degrees_of_freedom == 25 then 2.060
  elif $degrees_of_freedom == 26 then 2.056
  elif $degrees_of_freedom == 27 then 2.052
  elif $degrees_of_freedom == 28 then 2.048
  elif $degrees_of_freedom == 29 then 2.045
  elif $degrees_of_freedom == 30 then 2.042
  else 1.960
  end;

# distribution_with_confidence adds an exploratory paired-observation interval.
def distribution_with_confidence:
  . as $values
  | ($values | distribution) as $stats
  | if ($values | length) < 2
    then $stats + {
      confidence_95_lower: null,
      confidence_95_upper: null,
      confidence_method: "unavailable_fewer_than_two_pairs"
    }
    else
      ($stats.sample_stddev / (($values | length) | sqrt)
       * t95(($values | length) - 1)) as $margin
      | $stats + {
          confidence_95_lower: ($stats.mean - $margin),
          confidence_95_upper: ($stats.mean + $margin),
          confidence_method: "two_sided_student_t_paired_observations"
        }
    end;

($runs[0] // []) as $paired_runs
| ($controls[0] // []) as $control_runs
| ($paired_runs | map(select(.phase_order == "baseline ebpf")) | length) as $baseline_first_count
| ($paired_runs | map(select(.phase_order == "ebpf baseline")) | length) as $ebpf_first_count
| ($baseline_first_count == $ebpf_first_count) as $phase_order_balanced
| ($paired_runs | map(.comparison.latency_mean_change_percent) | distribution_with_confidence) as $latency_change
| ($paired_runs | map(.comparison.completion_latency_mean_change_percent) | distribution_with_confidence) as $completion_mean_change
| ($paired_runs | map(.comparison.completion_latency_p50_change_percent) | distribution_with_confidence) as $completion_p50_change
| ($paired_runs | map(.comparison.completion_latency_p95_change_percent) | distribution_with_confidence) as $completion_p95_change
| ($paired_runs | map(.comparison.completion_latency_p99_change_percent) | distribution_with_confidence) as $completion_p99_change
| ($control_runs | map(.comparison.latency_mean_change_percent) | distribution_with_confidence) as $control_signed_change
| ($control_runs | map(.comparison.latency_mean_absolute_change_percent) | distribution) as $control_absolute_change
| ($control_runs | map(.comparison.completion_latency_mean_absolute_change_percent) | distribution) as $control_completion_mean_absolute_change
| ($control_runs | map(.comparison.completion_latency_p50_absolute_change_percent) | distribution) as $control_completion_p50_absolute_change
| ($control_runs | map(.comparison.completion_latency_p95_absolute_change_percent) | distribution) as $control_completion_p95_absolute_change
| ($control_runs | map(.comparison.completion_latency_p99_absolute_change_percent) | distribution) as $control_completion_p99_absolute_change
| [
    if ($paired_runs | length) < 6
      then "fewer_than_six_paired_baseline_ebpf_iterations" else empty end,
    if ($phase_order_balanced | not)
      then "baseline_ebpf_phase_order_is_not_balanced" else empty end,
    if ($control_runs | length) < 2
      then "fewer_than_two_baseline_baseline_control_pairs" else empty end
  ] as $limitations
| {
    schema_version: "2",
    observed_at_utc: $observed_at_utc,
    vm: $vm,
    host: {
      kernel_release: $kernel_release,
      architecture: $architecture
    },
    build: $build[0],
    config_source: $config_source,
    workload: {
      duration_seconds: $duration_seconds,
      interval_seconds: $interval_seconds,
      warmup_seconds: $warmup_seconds,
      settle_seconds: $settle_seconds,
      target_rate_mib_per_sec: $rate_mib,
      rate_iops_per_job: $rate_iops_per_job,
      fio_jobs: 4,
      block_size_kib: 4,
      durable_fdatasync_every_writes: 1024,
      throughput_rate_limited: true
    },
    requested_design: {
      paired_iterations: $requested_iterations,
      control_pairs: $requested_control_pairs,
      minimum_paired_iterations_for_review: 6,
      minimum_control_pairs_for_review: 2,
      balanced_phase_order_required_for_review: true
    },
    runs: $paired_runs,
    control_runs: $control_runs,
    summary: {
      paired_iteration_count: ($paired_runs | length),
      control_pair_count: ($control_runs | length),
      baseline_first_count: $baseline_first_count,
      ebpf_first_count: $ebpf_first_count,
      phase_order_balanced: $phase_order_balanced,
      baseline_iops_mean: ($paired_runs | map(.baseline.fio.iops) | average),
      ebpf_iops_mean: ($paired_runs | map(.ebpf_enabled.fio.iops) | average),
      iops_overhead_percent_mean: ($paired_runs | map(.comparison.iops_overhead_percent) | average),
      bandwidth_change_percent_mean: ($paired_runs | map(.comparison.bandwidth_change_percent) | average),
      baseline_latency_mean_ns: ($paired_runs | map(.baseline.fio.latency_mean_ns) | distribution),
      ebpf_latency_mean_ns: ($paired_runs | map(.ebpf_enabled.fio.latency_mean_ns) | distribution),
      ratio_of_latency_means_change_percent: (
        ($paired_runs | map(.baseline.fio.latency_mean_ns) | average) as $baseline_mean
        | ($paired_runs | map(.ebpf_enabled.fio.latency_mean_ns) | average) as $ebpf_mean
        | if $baseline_mean > 0
          then (($ebpf_mean - $baseline_mean) / $baseline_mean * 100)
          else null end
      ),
      latency_mean_change_percent_mean: $latency_change.mean,
      paired_latency_mean_change_percent: $latency_change,
      paired_completion_latency_mean_change_percent: $completion_mean_change,
      paired_completion_latency_p50_change_percent: $completion_p50_change,
      paired_completion_latency_p95_change_percent: $completion_p95_change,
      paired_completion_latency_p99_change_percent: $completion_p99_change,
      control_latency_mean_signed_change_percent: $control_signed_change,
      control_latency_mean_absolute_change_percent: $control_absolute_change,
      control_completion_latency_mean_absolute_change_percent: $control_completion_mean_absolute_change,
      control_completion_latency_p50_absolute_change_percent: $control_completion_p50_absolute_change,
      control_completion_latency_p95_absolute_change_percent: $control_completion_p95_absolute_change,
      control_completion_latency_p99_absolute_change_percent: $control_completion_p99_absolute_change,
      collector_cpu_core_percent_mean: ($paired_runs | map(.ebpf_enabled.collector_resources.cpu_core_percent) | average),
      collector_cpu_core_percent: ($paired_runs | map(.ebpf_enabled.collector_resources.cpu_core_percent) | distribution),
      collector_max_rss_bytes_max: ($paired_runs | map(.ebpf_enabled.collector_resources.max_rss_bytes) | max),
      map_full_total: ($paired_runs | map(.ebpf_enabled.collector.map_full) | add),
      dropped_events_total: ($paired_runs | map(.ebpf_enabled.collector.dropped_events) | add),
      ring_buffer_lost_total: ($paired_runs | map(.ebpf_enabled.collector.ring_buffer_lost) | add),
      incomplete_at_window_end_total: ($paired_runs | map(.ebpf_enabled.collector.incomplete_at_window_end) | add)
    },
    performance_assessment: {
      status: (if ($limitations | length) == 0 then "manual_review_required" else "insufficient_evidence" end),
      automatic_performance_pass_fail: false,
      review_ready: (($limitations | length) == 0),
      paired_latency_confidence_interval_crosses_zero: (
        if $latency_change.confidence_95_lower == null
        then null
        else ($latency_change.confidence_95_lower <= 0 and $latency_change.confidence_95_upper >= 0)
        end
      ),
      natural_variance_measured: (($control_runs | length) >= 2),
      limitations: $limitations,
      conclusion: (
        if ($limitations | length) > 0
        then "More balanced paired observations and control/control variance measurements are required."
        elif ($latency_change.confidence_95_lower <= 0 and $latency_change.confidence_95_upper >= 0)
        then "The paired latency confidence interval crosses zero; no directional collector latency effect was resolved."
        else "A directional paired latency shift was observed, but it remains experimental and requires comparison with control variance and operational judgment."
        end
      )
    },
    safety_assessment: {
      status: "PASS",
      scope: "collector_lifecycle_attribution_privacy_and_bounded_instrumentation_only"
    },
    interpretation: [
      "Rate-limited fio throughput cannot establish zero collector overhead; latency distributions and collector resources must also be reviewed.",
      "Baseline/baseline control pairs estimate natural phase-to-phase variance but do not remove every host or storage confounder.",
      "The 95 percent interval uses a two-sided Student t interval over paired percentage changes and is exploratory for small samples.",
      "Collector CPU time does not directly measure all in-kernel eBPF execution cost.",
      "The safety PASS is separate from performance assessment and is not a production overhead guarantee."
    ],
    privacy: {
      process_arguments_collected: false,
      environment_collected: false,
      guest_files_collected: false,
      query_text_collected: false,
      table_data_collected: false,
      request_body_collected: false,
      response_body_collected: false,
      secrets_collected: false
    },
    result: "PASS",
    result_scope: "safety_only_performance_requires_manual_review"
  }
