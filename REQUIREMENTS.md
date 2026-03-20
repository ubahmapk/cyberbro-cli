# REQUIREMENTS

## Configuration

- Client configuration should be managed via a configuration file, in TOML format.
- The server address should be stored in the configuration file.
- The client should rely on the server configuration for "Observable" validation.
- The client should retrieve the list of available engines, on first run and on demand, from the server.
- The client should store available engines in the configuration file.
- The client should store a default output format in the configuration.
- The client should support a configurable request timeout (how long to wait for analysis to complete).
- The client should support a configurable polling interval (how frequently to check analysis status).
- The client should generate a default configuration file on first run if none exists.
- A subcommand (e.g., `config init`) should allow the user to (re-)initialize the configuration file interactively or with defaults.
- The client should be able to save a set of engines, using a label, to be used for a given observable type.
  - This set needs ONLY be configurable via the TOML file.

## Inputs

- All inputs and settings should be configurable through:
  - Environment variables
  - Command line options/flags or arguments
  - Configuration file settings
- Engines must be selectable for a given query as options, environment variables, or from a file, with each line representing a single engine
- Observables must be able to be specified as command line options, environment variables, or from a file, with each line representing a single observable.
- More than one observable must be able to be passed with a single query.
- A previous report must be able to be read from disk (from JSON format).
  - The previous report must be validated/sanitized prior to displaying it to the user.
  - The report should be colorized after sanitization and prior to be displayed to the user.
- The client should rely on the server to defang any observables.
- The client should support overriding the detected observable type via a CLI option or environment variable.
- The client should support bypassing the server-side analysis cache via a CLI option or environment variable.
- The client should be able to save a default set of engines for an otherwise unlabled or specified request.
- The client should be able to easily specify ALL engines run for a given request (and let the server figure out which engines can actually process the observable).

## Validation

- The client should rely on the server to validate observables.
- The client should rely on the server to determine the type of observable passed.
- The client should validate reports received from the server prior to displaying them to the user.
- TLS certificate verification must be enabled by default.
- The client should provide an option (CLI flag, environment variable, or config setting) to disable TLS verification, to support self-hosted instances with self-signed certificates.

## Output

- The client should display reports to the user in one of two formats:
  - human-readable (e.g. table)
  - JSON
- CSV may be added as a third format in the future.
- Both output formats should be colorized, when displayed on screen.
- The output format should also be accepted as a command line option.
- The output must be able to be written to disk as a JSON file (no colors should be saved with the file).
- The client should display progress or status feedback to the user while waiting for asynchronous analysis to complete (e.g., a spinner or status message).
- The client should support a quiet/non-interactive mode that suppresses all non-result output (progress, status messages), suitable for scripting and CI use.
- When writing output to disk, the user must be able to specify the output file path via a CLI option or environment variable.

## Exit Codes

- The client must exit with code `0` on success.
- The client must exit with a non-zero code on failure (e.g., network error, server error, validation failure, timeout).
- Exit codes should be documented and consistent, to support scripting and automation.

## Engine Discovery

- The client should provide a subcommand to list all available engines known to the client.
- The engine list should be filterable by observable type.
- Each engine entry should display its name and the observable types it supports.
- The engine list should be refreshable from the server on demand.
