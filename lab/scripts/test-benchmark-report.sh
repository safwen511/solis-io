#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly report_filter="${script_dir}/benchmark-report.jq"
test_dir="$(mktemp -d /tmp/solis-benchmark-report-test-XXXXXXXX)"

# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  rm -rf -- "$test_dir"
}
trap cleanup EXIT

for command in jq mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required test command is missing: ${command}" >&2
    exit 1
  }
done

printf '%s\n' '{"version":"test"}' >"${test_dir}/build.json"

jq -n '
  def fio($latency; $percent): {
    iops: 12800,
    bandwidth_bytes_per_sec: 52428800,
    latency_mean_ns: $latency,
    completion_latency_mean_ns: $latency,
    completion_latency_p50_ns: (50000 * (1 + $percent / 100)),
    completion_latency_p95_ns: (3000000 * (1 + $percent / 100)),
    completion_latency_p99_ns: (5000000 * (1 + $percent / 100))
  };
  def run($iteration; $order; $change): {
    iteration: $iteration,
    phase_order: $order,
    baseline: {fio: fio(500000; 0)},
    ebpf_enabled: {
      fio: fio((500000 * (1 + $change / 100)); $change),
      collector_resources: {
        cpu_core_percent: 1,
        max_rss_bytes: 32000000
      },
      collector: {
        map_full: 0,
        dropped_events: 0,
        ring_buffer_lost: 0,
        incomplete_at_window_end: 0
      }
    },
    comparison: {
      iops_overhead_percent: 0,
      bandwidth_change_percent: 0,
      latency_mean_change_percent: $change,
      completion_latency_mean_change_percent: $change,
      completion_latency_p50_change_percent: $change,
      completion_latency_p95_change_percent: $change,
      completion_latency_p99_change_percent: $change
    },
    result: "PASS"
  };
  [
    run(1; "baseline ebpf"; 10),
    run(2; "ebpf baseline"; -5),
    run(3; "baseline ebpf"; 8),
    run(4; "ebpf baseline"; -3),
    run(5; "baseline ebpf"; 6),
    run(6; "ebpf baseline"; -1)
  ]
' >"${test_dir}/runs.json"

jq -n '[
  {
    pair: 1,
    comparison: {
      latency_mean_change_percent: 7,
      latency_mean_absolute_change_percent: 7,
      completion_latency_mean_absolute_change_percent: 6,
      completion_latency_p50_absolute_change_percent: 5,
      completion_latency_p95_absolute_change_percent: 8,
      completion_latency_p99_absolute_change_percent: 9
    }
  },
  {
    pair: 2,
    comparison: {
      latency_mean_change_percent: -5,
      latency_mean_absolute_change_percent: 5,
      completion_latency_mean_absolute_change_percent: 4,
      completion_latency_p50_absolute_change_percent: 3,
      completion_latency_p95_absolute_change_percent: 6,
      completion_latency_p99_absolute_change_percent: 7
    }
  }
]' >"${test_dir}/controls.json"

# render_report writes report in the script's deterministic report format.
render_report() {
  local runs_path=$1
  local controls_path=$2
  local requested_iterations=$3
  local requested_control_pairs=$4
  local output_path=$5
  jq -n \
    --arg observed_at_utc '2026-08-13T00:00:00Z' \
    --arg vm b-stress \
    --arg kernel_release test \
    --arg architecture x86_64 \
    --arg config_source test \
    --argjson duration_seconds 60 \
    --argjson interval_seconds 1 \
    --argjson warmup_seconds 10 \
    --argjson settle_seconds 20 \
    --argjson rate_mib 50 \
    --argjson rate_iops_per_job 3200 \
    --argjson requested_iterations "$requested_iterations" \
    --argjson requested_control_pairs "$requested_control_pairs" \
    --slurpfile build "${test_dir}/build.json" \
    --slurpfile runs "$runs_path" \
    --slurpfile controls "$controls_path" \
    -f "$report_filter" >"$output_path"
}

render_report \
  "${test_dir}/runs.json" \
  "${test_dir}/controls.json" \
  6 2 \
  "${test_dir}/review-ready.json"

jq -e '
  .schema_version == "2"
  and .summary.paired_iteration_count == 6
  and .summary.control_pair_count == 2
  and .summary.phase_order_balanced == true
  and .summary.paired_latency_mean_change_percent.count == 6
  and .summary.paired_completion_latency_p95_change_percent.count == 6
  and .summary.control_completion_latency_p99_absolute_change_percent.median == 8
  and .summary.collector_cpu_core_percent_mean == 1
  and .performance_assessment.status == "manual_review_required"
  and .performance_assessment.review_ready == true
  and .performance_assessment.automatic_performance_pass_fail == false
  and .safety_assessment.status == "PASS"
  and .result_scope == "safety_only_performance_requires_manual_review"
  and all(.privacy[]; . == false)
' "${test_dir}/review-ready.json" >/dev/null

jq '.[0:3]' "${test_dir}/runs.json" >"${test_dir}/short-runs.json"
printf '%s\n' '[]' >"${test_dir}/no-controls.json"
render_report \
  "${test_dir}/short-runs.json" \
  "${test_dir}/no-controls.json" \
  3 0 \
  "${test_dir}/insufficient.json"

jq -e '
  .performance_assessment.status == "insufficient_evidence"
  and .performance_assessment.review_ready == false
  and (.performance_assessment.limitations | index("fewer_than_six_paired_baseline_ebpf_iterations") != null)
  and (.performance_assessment.limitations | index("baseline_ebpf_phase_order_is_not_balanced") != null)
  and (.performance_assessment.limitations | index("fewer_than_two_baseline_baseline_control_pairs") != null)
  and .summary.paired_latency_mean_change_percent.confidence_95_lower != null
  and .summary.control_latency_mean_absolute_change_percent.count == 0
  and .performance_assessment.automatic_performance_pass_fail == false
' "${test_dir}/insufficient.json" >/dev/null

echo "benchmark report statistics tests: PASS"
