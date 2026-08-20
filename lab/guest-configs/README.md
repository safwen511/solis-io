# Lab guest configuration

These are the reviewable configuration files copied into the optional Solis
tenant lab. They reproduce the two fixed paths used by the demonstrations:

```text
a-client -> a-web -> a-db
b-client -> b-web -> b-db
```

The deployment scripts render only the documented `@NAME@` placeholders and
install the results at fixed guest paths:

| Source | Guest | Destination |
|---|---|---|
| `web/solis-workload.service.template` | `a-web`, `b-web` | `/etc/systemd/system/solis-workload.service` |
| `web/nginx-solis-workload.conf` | `a-web`, `b-web` | `/etc/nginx/sites-available/solis-workload` |
| `postgresql/pg-hba-solis.conf.template` | `a-db`, `b-db` | appended once to the active `pg_hba.conf` |
| `postgresql/postgresql-listen.sql` | `a-db`, `b-db` | applied with `psql` |
| `postgresql/solis-workload-retention.service` | `a-db`, `b-db` | `/etc/systemd/system/solis-workload-retention.service` |
| `postgresql/solis-workload-retention.timer` | `a-db`, `b-db` | `/etc/systemd/system/solis-workload-retention.timer` |
| `client/solis-steady-traffic.service.template` | `a-client`, `b-client` | `/etc/systemd/system/solis-steady-traffic.service` |
| `stress/solis-moderate-pressure.service.template` | `b-stress` | `/etc/systemd/system/solis-moderate-pressure.service` |

Application programs and SQL schema/retention statements remain under
`lab/workloads/`. The templates contain only fixed lab identities and the
existing demonstration credential; they must not be reused for production.
Use the scripts in `lab/scripts/` instead of manually rendering placeholders.
