# Requirements Coverage Analysis

Generated: 2026-03-20

---

## Configuration

| Requirement | Status |
|---|---|
| TOML config file | ✅ Implemented |
| Server address in config | ✅ Implemented |
| Rely on server for Observable validation | ✅ Implemented (passed to server) |
| Retrieve available engines from server on first run / on demand | ❌ Not implemented — engine list is hardcoded in `engines.rs` |
| Store available engines in config file | ❌ Not implemented |
| Default output format in config | ❌ Not implemented — no config field for this |
| Configurable request timeout | ✅ Implemented |
| Configurable polling interval | ✅ Implemented |
| Generate default config on first run | ⚠️ Partially — graceful degradation exists, but no config is written on first run |
| `config init` subcommand | ❌ Not implemented |
| Named engine presets per observable type (TOML only) | ❌ Not implemented |

## Inputs

| Requirement | Status |
|---|---|
| Config via env vars, CLI flags, and config file | ✅ Implemented |
| Engines selectable via CLI, env var, or file | ⚠️ CLI and env var yes; file input for engines not implemented |
| Observables from CLI, env var, or file | ✅ Implemented |
| Multiple observables per query | ✅ Implemented |
| Read previous report from disk (JSON) | ❌ Not implemented |
| Validate/sanitize previous report before display | ❌ Not implemented |
| Colorize previous report after sanitization | ❌ Not implemented |
| Server defangs observables | ✅ Client defangs locally before sending; req passes to server |
| Override detected observable type | ✅ Implemented (`--type` flag) |
| Bypass server-side cache | ✅ Implemented (`--ignore-cache`) |
| Default engine set for unlabeled requests | ✅ Implemented |
| Specify ALL engines for a request | ✅ Implemented (`--all-engines`) |

## Validation

| Requirement | Status |
|---|---|
| Rely on server to validate observables | ✅ Implemented |
| Rely on server to determine observable type | ✅ Implemented |
| Validate reports from server before displaying | ⚠️ Minimal — results are rendered directly from raw JSON without schema validation |
| TLS verification enabled by default | ✅ Implemented |
| Option to disable TLS verification | ✅ Implemented (`--no-tls-verify`, env var, config) |

## Output

| Requirement | Status |
|---|---|
| Table format | ✅ Implemented |
| JSON format | ✅ Implemented |
| CSV format (future) | ✅ Implemented (ahead of schedule) |
| Colorized output | ✅ Implemented |
| Output format via CLI option | ✅ Implemented |
| Write output to disk as JSON (no colors) | ❌ Not implemented |
| Progress/status feedback while waiting | ✅ Implemented (spinner) |
| Quiet/non-interactive mode | ✅ Implemented (`--quiet`) |
| Specify output file path via CLI or env var | ❌ Not implemented |

## Exit Codes

| Requirement | Status |
|---|---|
| Exit `0` on success | ✅ Implemented |
| Non-zero exit on failure | ✅ Implemented |
| Documented, consistent exit codes | ⚠️ Minimal — only `0`/`1` used; no differentiation by error type |

## Engine Discovery

| Requirement | Status |
|---|---|
| Subcommand to list available engines | ✅ Implemented (`engines list`) |
| Filter engine list by observable type | ✅ Implemented |
| Display engine name and supported types | ✅ Implemented |
| Refresh engine list from server on demand | ❌ Not implemented — list is hardcoded |

---

## Outstanding Work

### High Priority (core functionality gaps)

1. **Server-driven engine discovery** — fetch and cache engine list from server instead of hardcoding
2. **Write output to file** — `--output-file` / env var support for JSON output to disk
3. **`config init` subcommand** — interactive or default config initialization
4. **Default config generation on first run** — write a starter config if none exists

### Medium Priority

5. **Engines from file** — `--engines-file` to read engine list from a file (one per line)
6. **Default output format in config** — add `default_output` field to TOML config
7. **Named engine presets** — label-based engine sets in config TOML

### Lower Priority / Polish

8. **Read and display previous report from disk** — load saved JSON, validate, colorize, and render
9. **Differentiated exit codes** — distinct codes for network error, timeout, validation failure, etc.
10. **Server report validation** — schema validation of API responses before rendering
