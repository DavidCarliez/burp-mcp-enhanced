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
- Proxy history indexes refer to Burp's current in-memory history.
- If history is cleared or heavily changed, recount and rediscover indexes.

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
    "statusCode",
    "contentType",
    "requestContentLength",
    "responseContentLength",
    "hasRequestBody",
    "hasResponseBody",
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
  "count": 20,
  "fields": ["method", "path", "host", "statusCode", "contentType", "requestContentLength"]
}
```

Use tool: `get_proxy_http_history_filtered`

## Index and Pagination Rules

- `index` is 1-based and points to a single proxy history row.
- `offset` is 0-based and used only by paginated list tools.
- Prefer `get_latest_proxy_http_history` when you want newest items.
- Prefer `get_proxy_http_history_since` when polling after a known index.

Do not mix `index` and `offset`.

## Compact Fields

Use compact fields first:

- `method`
- `path`
- `host`
- `statusCode`
- `contentType`
- `requestContentLength`
- `responseContentLength`
- `hasRequestBody`
- `hasResponseBody`
- `requestLine`
- `responseLine`
- `notes`

Avoid `request` and `response` during broad scans. They can be huge.

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

- Make one mutation class at a time when testing hypotheses.
- Compare status code, response length, content type, and semantic body differences.
- Preserve authentication unless the test specifically targets auth behavior.
- Do not fuzz aggressively through this tool. It sends live HTTP traffic.
- For promising candidates, create a Repeater tab.

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
  "count": 30,
  "fields": ["method", "path", "host", "statusCode", "hasResponseBody"]
}
```

2. Pull request headers for auth context.
3. Replay with a neighboring object ID in `replacePath`.
4. Compare response status and body semantics.
5. Send confirmed candidate to Repeater.

### JSON Input Handling

1. Filter JSON requests with bodies:

```json
{
  "hasRequestBody": true,
  "contentTypeContains": "json",
  "newestFirst": true,
  "count": 30,
  "fields": ["method", "path", "host", "statusCode", "requestContentLength"]
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
  "count": 20,
  "fields": ["method", "path", "host", "contentType", "responseContentLength"]
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
  "fields": ["method", "path", "host", "statusCode", "contentType"]
}
```

4. Process only the new entries.

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
- Preserve history and request security gates.
- Run `./gradlew test`.
- Build with `./gradlew embedProxyJar`.
- Installable JAR: `build/libs/burp-mcp-all.jar`
- Do not edit the stdio proxy JAR for tool behavior changes.

## Common Mistakes

- Dumping complete history instead of compact fields.
- Pulling full request and response bodies before selecting candidates.
- Confusing 1-based `index` with 0-based `offset`.
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
