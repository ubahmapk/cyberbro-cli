# Architecture Notes: Displaying the Analysis Results URL

This document explains the design decisions made when adding the server results
URL to the CLI output. It is written for someone learning Rust who is familiar
with Python.

---

## What was added

When you submit observables to Cyberbro the server responds with both an
`analysis_id` and a `link` — the URL of the results page on the web UI. Before
this change, `link` was silently discarded. Now it is:

- Printed as a footer line after the table output
- Wrapped as a top-level `"results_url"` field in JSON output
- Added as a column in every CSV row

---

## Decision 1: Named struct (`AnalysisOutcome`) instead of a tuple

### Before

```rust
pub async fn analyze_and_wait(...) -> Result<(String, Vec<serde_json::Value>)>
```

The function returned a 2-tuple of `(analysis_id, results)`. To also return
the URL we needed a third value.

### After

```rust
pub struct AnalysisOutcome {
    pub analysis_id: String,
    pub results_url: String,
    pub results: Vec<serde_json::Value>,
}

pub async fn analyze_and_wait(...) -> Result<AnalysisOutcome>
```

### Why a struct?

Tuples are positional. A 3-tuple `(String, String, Vec<…>)` leaves every
reader guessing: which `String` is the ID and which is the URL? Mistakes are
easy and the compiler cannot help — both fields have the same type.

A named struct is self-documenting. At the call site:

```rust
let client::AnalysisOutcome { analysis_id, results_url, results: result_data } = http
    .analyze_and_wait(...)
    .await?;
```

The destructuring pattern names every field explicitly. If a future developer
adds a fourth field (e.g. `engine_count: usize`), they add it to the struct
and the compiler will point out every call site that needs updating — Rust's
exhaustive pattern matching guarantees nothing is silently ignored.

In Python you would probably return a `dataclass` or `NamedTuple` for the same
reason. This is the Rust equivalent.

### Ownership and cloning

The `AnalyzeResponse` value returned by `submit()` is owned by the function.
We must clone both fields before the polling loop so they can be moved into
the returned `AnalysisOutcome` later:

```rust
let submission = self.submit(text, engines, ignore_cache).await?;
let analysis_id = submission.analysis_id.clone();
let results_url  = submission.link.clone();
```

In Python strings are reference-counted and assignment is always safe. In Rust,
a `String` is uniquely owned heap data. Once you move it you can no longer use
the source. `.clone()` creates a new independent copy — cheap for short strings
like IDs and URLs.

---

## Decision 2: `results_url` as a render-time parameter, not embedded in results data

### The alternative

We could have injected `results_url` directly into each `serde_json::Value`
result object before rendering:

```rust
for item in &mut result_data {
    item["results_url"] = json!(results_url);
}
```

### Why we didn't

The `Vec<serde_json::Value>` comes from the server's `/api/results` endpoint.
Each element describes one observable — its engine results, observable value,
type, etc. The `results_url` belongs to the *submission*, not to any individual
observable. Injecting it into the per-observable data would:

1. Misrepresent the data model (a URL about the whole analysis appearing as if
   it belongs to one IP or domain)
2. Repeat identical data N times (once per observable)
3. Pollute the `flatten_result` / table-rendering logic with a special-case
   field to filter out

Passing it separately keeps the data clean and the rendering code honest. Each
rendering function (`render_table`, `render_json`, `render_csv`) decides how
best to display it for its own format.

---

## Decision 3: JSON output wraps results in an object

### Before

```json
[
  { "observable": "8.8.8.8", "virustotal": { ... }, ... },
  ...
]
```

### After

```json
{
  "results_url": "https://server/link/to/results",
  "results": [
    { "observable": "8.8.8.8", "virustotal": { ... }, ... },
    ...
  ]
}
```

### Why wrap instead of appending?

Appending a sentinel object to the array (e.g. `{ "type": "metadata",
"results_url": "..." }`) would be simpler code but breaks every consumer that
iterates the array and tries to access `"observable"` on each element.

Wrapping in an outer object is a well-understood JSON convention for
"response envelope". The URL is a first-class, machine-parseable field. Tools
like `jq` can easily extract it: `jq '.results_url'`.

### How it's implemented: `serde_json::json!` macro

```rust
let output = serde_json::json!({
    "results_url": results_url,
    "results": results,
});
println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
```

`serde_json::json!` is a macro that constructs a `serde_json::Value` from a
JSON-like literal at compile time. It is the Rust equivalent of a Python dict
literal passed to `json.dumps()`. The macro interpolates any Rust expression
as a value — strings, numbers, other `Value`s, slices — and handles the type
coercions automatically.

---

## Decision 4: CSV adds `results_url` as a column in every row

CSV is a flat format with no nesting or metadata sections. The two sane options
were:

1. Add a header comment line (`# results_url: https://...`) — non-standard and
   breaks parsers that expect only header + data rows
2. Add a `results_url` column repeated in every data row — standard, parseable,
   and consistent with how tools like Excel or pandas work

We chose option 2. The column is seeded into `all_keys` before the loop so it
sorts consistently (alphabetically, before most other keys starting with
letters further in the alphabet), and each row gets the value inserted into its
`BTreeMap` before the key-set union step.

---

## Table output: footer placement

The URL is printed *after* all observable tables, not inside any one table, for
the same reason it is not embedded in the per-observable data: it belongs to
the analysis as a whole. The format mirrors the existing separator style used
above each observable block (`"─".repeat(72)`), giving a consistent visual
rhythm:

```
Observable: 8.8.8.8  [IPv4]
────────────────────────────────────────────────────────────────────────
┌──────────────┬──────────────────────────────────────────────┐
│ Engine       │ Result                                       │
├──────────────┼──────────────────────────────────────────────┤
│ abuseipdb    │ Risk: 0%  Reports: 0  Country: US  ISP: ...  │
└──────────────┴──────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────────────
Results URL: https://server/results/abc123
```

The URL is rendered in cyan (matching the engine name color), consistent with
the color conventions used throughout the rest of the output.
