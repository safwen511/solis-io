# Solis I/O Workload Experiment — First Noisy Neighbor Signal

Experiment time: 2026-08-08T17:48:25Z

## Topology

Victim workload:

    tenant-a:
    a-client -> a-web -> a-db

Noisy neighbor:

    tenant-b:
    b-stress -> fio random write workload

The tenants do not communicate with each other. The slowdown is caused by shared host storage pressure.

## HTTP workload

The workload sends HTTP requests from the tenant client to the tenant web server.

Each /write request inserts one row into PostgreSQL.

Workload shape:

    ab -l -n 1000 -c 20 http://192.168.130.20/write

## Results

| Phase | Requests/sec | Mean time/request | Failed requests |
|---|---:|---:|---:|
| Baseline | 174.14 | 114.850 ms | 0 |
| During b-stress fio | 133.02 | 150.359 ms | 0 |
| Post-noise | 150.88 | 132.560 ms | 0 |

## Impact during noisy-neighbor phase

Throughput dropped by approximately 23.6%.

Mean request latency increased by approximately 30.9%.

## fio noise

b-stress generated:

    IOPS: 59.9k
    Bandwidth: 234 MiB/s
    Disk util: 84.86%

## Interpretation

This confirms the Solis I/O thesis:

    A tenant workload can slow down because another isolated tenant VM creates shared host storage pressure.

Next step: make Solis parse these reports automatically and later replace report parsing with live host-side block telemetry.
