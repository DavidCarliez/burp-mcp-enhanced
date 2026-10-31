# Burp MCP Enhanced - Agent Operating Guide

This repo ships a Burp Suite MCP extension for security research agents. If you are an agent connected to this MCP server, your job is to use Burp traffic efficiently, not to dump history blindly.

## Mission

Use Burp as an exploitation workbench:

1. Discover interesting HTTP traffic from proxy history.
2. Triage using compact metadata.
3. Pull bounded request or response slices only for candidates.
4. Replay captured requests with small mutations.
5. Mark useful findings for human follow-up.
6. Escalate confirmed primitives into Repeater, Intruder, or a vulnerability report.

Do not waste context on full request/response dumps unless you already have a candidate.

## Connection Model

The Burp extension exposes MCP tools from the running Burp instance. The stdio proxy only forwards calls to the extension SSE server.

Important consequences:

- New tools appear only after the updated extension JAR is loaded in Burp.
- Tool behavior lives in the Burp extension JAR, not in the proxy JAR.
- Proxy history indexes are global 1-based positions in Burp's current in-memory history. Every tool reports and accepts the same number.
- If history is cleared or heavily changed, recount and rediscover indexes; `get_proxy_http_history_since` reports `historyReset` when a stored cursor no longer exists.

## First Moves on a Target

Start with counts and compact history, not bodies.

1. Count HTTP history:

```json
{}
```

Use tool: `get_proxy_http_history_count`

2. Fetch newest compact entries:

```json
{
  "count": 20,
  "fields": [
    "method",
    "path",
    "host",
    "port",
    "statusCode",
    "mimeType",
    "requestContentLength",
    "responseContentLength",
    "notes"
  ]
}
```

Use tool: `get_latest_proxy_http_history`

3. Filter for high-signal shapes:

```json
{
  "method": "POST",
  "hasRequestBody": true,
  "newestFirst": true,
  "offset": 0,
  "count": 20,
  "fields": ["method", "path", "host", "statusCode", "mimeType", "requestContentLength"]
}
```

Use tool: `get_proxy_http_history_filtered`

## Index and Pagination Rules

- `index` is the global 1-based position of one proxy history row. Paginated lists, regex search, structured filtering, slices, replay, notes, highlights, Repeater and Intruder all use that same number.
- `id` is Burp's own item id and is reported beside `index`.
- `offset` is 0-based and only used by list tools.
- `_filtered` returns `totalMatches`, `offset`, `returned`, `hasMore` and `items`. Zero hits means `totalMatches: 0`, not "end of items".
- Prefer `get_latest_proxy_http_history` when you want newest items.
- Prefer `get_proxy_http_history_since` when polling after a known index; use its `nextIndex` for the following poll.

Do not mix `index` and `offset`, and never renumber regex hits by their position in the match list.

## Output Limits

- `count` up to 500, `length` up to 200000 characters, `bodyPreviewLength` up to 20000.
- One history item is capped at 5000 characters of JSON; long strings end with `... (truncated)` and the document stays parseable.
- Send and replay responses are cut at 200000 characters with the original length appended.
- A missing request or response is JSON `null`, not a placeholder string.

## Compact Fields

Use compact fields first:

- `index`, `id` (always present)
- `method`
- `path`
- `host`
- `port`
- `statusCode`
- `mimeType`
- `time`
- `requestContentLength`
- `responseContentLength`
- `notes`

Avoid `request` and `response` during broad scans. They can be huge.

## Finding a Value in Context

When you know what the value looks like but not where it lives, search instead of paging:

```json
{"regex": "AKIA[0-9A-Z]{16}", "count": 5, "offset": 0}
```

Tool: `search_proxy_http_history`. Each hit gives `message`, `part`, `offset` and 40 characters of context either side. Widen it by feeding the offset to `get_proxy_http_history_body` (part `body`) or `get_proxy_http_history_message_slice` with `part` `full`.

Do not page item dumps or body slices hunting for a value that one search finds.

## Pulling Message Data

When a candidate index looks interesting, use bounded slices.

Headers first:

```json
{
  "index": 42,
  "message": "request",
  "part": "headers",
  "offset": 0,
  "length": 4000
}
```

Use tool: `get_proxy_http_history_message_slice`

Then body only if needed:

```json
{
  "index": 42,
  "message": "response",
  "part": "body",
  "offset": 0,
  "length": 8000
}
```

Valid `message` values: `request`, `response`.

Valid `part` values: `headers`, `body`, `full`.

Prefer `headers` or `body` over `full` unless you have a specific reason.

## Replay Workflow

Use `send_http_request_from_history` to validate a primitive from a captured request.

Example path mutation:

```json
{
  "index": 42,
  "replacePath": "/api/users/124",
  "replaceHeaders": {
    "X-Burp-MCP-Probe": "idor-test"
  }
}
```

Example body mutation:

```json
{
  "index": 42,
  "replaceBody": "{\"role\":\"admin\"}",
  "replaceHeaders": {
    "Content-Type": "application/json"
  }
}
```

Replay rules:

- Headers in `replaceHeaders` are updated when present and added when missing, so injecting `Authorization` or `Cookie` works.
- Replay passes through the same per-target approval gate as `send_http1_request`, evaluated on the mutated request's target.
- Make one mutation class at a time when testing hypotheses.
- Compare status code, response length, content type, and semantic body differences.
- Preserve authentication unless the test specifically targets auth behavior.
- Do not fuzz aggressively through this tool. It sends live HTTP traffic.
- Prefer `send_http_request_from_history_with_diff` when validating a hypothesis because it returns compact before/after evidence.
- For promising candidates, annotate the Burp row and create a Repeater tab.

## Replay With Diff

Use `send_http_request_from_history_with_diff` when testing a candidate. It replays a captured request with optional mutation, then returns baseline and mutated response fingerprints plus deltas.

```json
{
  "index": 42,
  "replacePath": "/api/users/124",
  "replaceHeaders": {
    "X-Burp-MCP-Probe": "idor-test"
  },
  "bodyPreviewLength": 1000
}
```

Look at:

- `statusChanged`
- `contentTypeChanged`
- `bodyLengthDelta`
- `bodyHashChanged`
- `similarity`
- `headerNamesAdded`
- `headerNamesRemoved`
- `preview.firstDifference`

A useful result is not just a changed hash. Prefer candidates with stable success status, similar structure, and meaningful semantic body differences.

## Annotating Burp History

Use annotations so the human and the next agent can resume from Burp itself.

Set or append a note:

```json
{
  "index": 42,
  "note": "MCP candidate: possible IDOR. /api/users/124 returned 200 with similar JSON shape."
}
```

Tools:

- `set_proxy_http_history_note`
- `append_proxy_http_history_note`

Set a highlight:

```json
{
  "index": 42,
  "highlight": "red"
}
```

Tool: `set_proxy_http_history_highlight`

Color convention:

- `red`: high-value or likely vulnerability
- `orange`: needs manual review
- `yellow`: suspicious but weak
- `green`: tested and likely safe
- `cyan`: auth/session behavior
- `blue`: recon or coverage marker
- `pink` or `magenta`: parser, weirdness, or error behavior
- `gray`: deprioritized
- `none`: clear highlight

## Repeater and Intruder Handoff

Use Repeater when a candidate needs manual refinement:

```json
{
  "index": 42,
  "tabName": "idor candidate 42"
}
```

Tool: `create_repeater_tab_from_history`

Use Intruder only when you have a clear parameter or path segment to attack:

```json
{
  "index": 42,
  "tabName": "user id sweep"
}
```

Tool: `send_to_intruder_from_history`

## Bug-Hunting Playbooks

### IDOR or Authorization Bypass

1. Filter for authenticated API requests:

```json
{
  "method": "GET",
  "pathContains": "/api/",
  "newestFirst": true,
  "offset": 0,
  "count": 30,
  "fields": ["method", "path", "host", "statusCode", "responseContentLength"]
}
```

2. Pull request headers for auth context.
3. Replay with a neighboring object ID using `send_http_request_from_history_with_diff`.
4. Review status, body length delta, hash change, similarity, and first difference.
5. If promising, append a note, set a highlight, and send confirmed candidate to Repeater.

### JSON Input Handling

1. Filter JSON requests with bodies:

```json
{
  "hasRequestBody": true,
  "contentTypeContains": "json",
  "newestFirst": true,
  "offset": 0,
  "count": 30,
  "fields": ["method", "path", "host", "statusCode", "mimeType", "requestContentLength"]
}
```

2. Slice the request body.
3. Replay one controlled mutation.
4. Watch for parser errors, reflected data, type confusion, authz deltas, or server errors.

### Error Surface Discovery

1. Filter 500 responses:

```json
{
  "statusCode": 500,
  "newestFirst": true,
  "offset": 0,
  "count": 20,
  "fields": ["method", "path", "host", "mimeType", "responseContentLength"]
}
```

2. Slice response headers and first body chunk.
3. Determine whether the error leaks stack traces, framework versions, SQL errors, paths, or debug data.

### Polling New Traffic

1. Call `get_proxy_http_history_count` before browsing or crawling.
2. Browse the app or trigger crawler activity.
3. Call `get_proxy_http_history_since` using the previous count as `afterIndex`:

```json
{
  "afterIndex": 120,
  "count": 50,
  "fields": ["method", "path", "host", "statusCode", "mimeType"]
}
```

4. Process only the new entries and continue from `nextIndex`.

## Safety and Scope

- Treat replay tools as live traffic tools.
- Do not run broad fuzzing loops unless explicitly authorized.
- Do not mutate destructive methods like `DELETE`, payment flows, account settings, or admin actions without scope confirmation.
- Prefer Repeater handoff for risky tests.
- If the target is out of scope, stop and report the blocker.

## If You Are Modifying This Repo

Most agents using this file should operate the MCP server, not change it. If you are explicitly asked to develop the extension:

- Main tool code: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Main tests: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`
- Add failing tests first.
- Preserve history and request security gates (`DataAccessSecurity`, `HttpRequestSecurity`).
- Run `./gradlew test`.
- Build with `./gradlew embedProxyJar`.
- Installable JAR: `build/libs/burp-mcp-all.jar`
- Do not edit the stdio proxy JAR for tool behavior changes.

## Common Mistakes

- Dumping complete history instead of compact fields.
- Pulling full request and response bodies before selecting candidates.
- Confusing global 1-based `index` with 0-based `offset`.
- Assuming WebSocket tools have HTTP feature parity.
- Replaying requests without understanding the side effect.
- Forgetting that Burp must load the latest extension JAR before tools appear.

## Success Criteria

A good agent session produces:

- A short list of candidate indexes with reasons.
- Evidence from bounded slices, not full dumps.
- Replay deltas for confirmed candidates.
- Repeater or Intruder tabs for promising leads.
- A concise vulnerability note when impact is real.
