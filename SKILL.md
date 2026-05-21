---
name: burp-mcp-enhanced
description: Use when working on or operating the DavidCarliez/burp-mcp-enhanced fork of PortSwigger's Burp MCP server. Explains architecture, build/test workflow, proxy history tools, structured triage, replay from history, and common traps for agents.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [burp, mcp, security-research, proxy-history, kotlin, montoya]
    related_skills: [native-mcp, test-driven-development, cve-hunting]
---

# Burp MCP Enhanced

## Overview

This repo is a private enhanced fork of PortSwigger's Burp Suite MCP server:

- Fork: `DavidCarliez/burp-mcp-enhanced`
- Upstream: `PortSwigger/mcp-server`
- Primary artifact: `build/libs/burp-mcp-all.jar`
- Main code: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Main tests: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

The extension runs inside Burp Suite and exposes Burp functionality as MCP tools over a local SSE server. The bundled `mcp-proxy-all.jar` is only a stdio-to-SSE bridge for clients that cannot speak SSE directly. Tool behavior lives in the Burp extension JAR, not in the proxy JAR.

This fork is optimized for security research agents. The important improvement is efficient proxy history navigation and triage: agents can count, fetch latest items, fetch by stable 1-based index, request compact metadata fields, slice headers or bodies, filter history by structured attributes, and replay captured requests with mutations.

## When to Use

Use this skill when:

- Modifying the Burp MCP extension.
- Teaching an agent how to operate this fork through MCP tools.
- Adding or testing new Burp tools backed by the Montoya API.
- Building an installable `burp-mcp-all.jar`.
- Debugging why a tool does not appear in an MCP client.
- Designing CVE-hunting workflows that use Burp proxy history as the source of truth.

Do not use this skill for generic MCP server configuration unrelated to Burp. Use the `native-mcp` skill for Hermes MCP client setup.

## Architecture

### Runtime pieces

1. **Burp extension JAR**
   - Built by `./gradlew embedProxyJar`.
   - Loaded in Burp under `Extensions -> Add -> Java`.
   - Starts the MCP SSE server, defaulting to `http://127.0.0.1:9876`.
   - Owns the actual tool registry and all Montoya API calls.

2. **Embedded stdio proxy JAR**
   - Packaged into the final all-in-one JAR.
   - Extracted or configured for clients that only support stdio MCP.
   - Forwards `tools/list` and `tools/call` to the extension SSE server.
   - Does not need modification when adding Burp tools.

3. **MCP client**
   - Can connect directly to SSE or through the stdio proxy.
   - Discovers tools dynamically from the running Burp extension.
   - If a new tool is missing, rebuild and reload the Burp extension first.

### Source layout

- `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
  - Tool definitions.
  - Serializable input data classes.
  - Proxy history serialization helpers.
  - History filtering, slicing, replay, Repeater, Intruder, encoding, Collaborator, and config tools.

- `src/main/kotlin/net/portswigger/mcp/McpTool.kt`
  - Generic MCP tool wrapper logic.
  - Tool names are derived from serializable data class names.

- `src/main/kotlin/net/portswigger/mcp/serialization.kt`
  - Serialization helpers for request and response objects.

- `src/main/kotlin/net/portswigger/mcp/HistoryAccessSecurity.kt`
  - Permission and safety checks for exposing history.

- `src/main/kotlin/net/portswigger/mcp/HttpRequestSecurity.kt`
  - Permission and safety checks for sending HTTP requests.

- `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`
  - Unit and integration coverage for tool behavior.

## Tool Naming Rules

Tool names are derived from Kotlin data class names by converting PascalCase to snake_case.

Examples:

- `GetLatestProxyHttpHistory` -> `get_latest_proxy_http_history`
- `GetProxyHttpHistoryByIndex` -> `get_proxy_http_history_by_index`
- `GetProxyHttpHistoryMessageSlice` -> `get_proxy_http_history_message_slice`
- `SendHttpRequestFromHistory` -> `send_http_request_from_history`

When adding a tool:

1. Add an `@Serializable data class` for the input parameters.
2. Register the tool with `mcpTool<YourDataClass>("description") { ... }`.
3. Add tests in `ToolsKtTest.kt` before implementation.
4. Run targeted tests, then the full suite.

## Enhanced Proxy History Model

Proxy HTTP history uses **1-based indexes** for agent-facing APIs. Index `1` means the first item in Burp's current proxy history list. This is deliberate because humans and agents discuss Burp history as numbered rows.

Core concepts:

- `index`: stable 1-based pointer into the current history array.
- `count`: maximum number of records to return.
- `offset`: 0-based pagination offset for existing paginated tools.
- `newestFirst`: returns newest entries first without needing to know the final offset.
- `fields`: optional allowlist for compact output.

Do not dump full requests and responses by default. Start with compact fields, then fetch a bounded slice only for the item that matters.

## Efficient Agent Workflow

Use this pattern when triaging Burp traffic:

1. Count the history.
2. Fetch latest compact metadata.
3. Filter for the interesting shape.
4. Pull headers or body slices only for candidates.
5. Replay with a minimal mutation.
6. Send to Repeater or Intruder only after finding a useful primitive.

Recommended first call:

```json
{
  "count": 20,
  "fields": ["method", "path", "host", "statusCode", "contentType", "requestContentLength", "responseContentLength", "hasRequestBody", "hasResponseBody", "notes"]
}
```

Good candidate fields:

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

Avoid requesting `request` and `response` for broad history scans. That burns context and hides signal.

## Enhanced HTTP History Tools

### `get_proxy_http_history_count`

Returns total proxy HTTP history entries. Optional `regex` applies a regex filter.

Use before pagination or when checking if new traffic arrived.

```json
{"regex": "api|graphql|admin"}
```

### `get_latest_proxy_http_history`

Returns newest proxy HTTP history entries without calculating offsets.

```json
{
  "count": 10,
  "fields": ["method", "path", "host", "statusCode", "contentType"]
}
```

### `get_proxy_http_history_by_index`

Fetches exactly one history item by 1-based index.

```json
{
  "index": 42,
  "fields": ["method", "path", "host", "statusCode", "requestLine", "responseLine"]
}
```

### `get_proxy_http_history_since`

Fetches entries added after a known 1-based index.

```json
{
  "afterIndex": 120,
  "count": 25,
  "fields": ["method", "path", "host", "statusCode"]
}
```

Use this for polling workflows. Store the last seen index externally, then ask for entries after it.

### `get_proxy_http_history_filtered`

Filters HTTP history using structured metadata.

Parameters:

- `method`
- `host`
- `pathContains`
- `statusCode`
- `hasRequestBody`
- `hasResponseBody`
- `contentTypeContains`
- `newestFirst`
- `count`
- `fields`

Example, newest JSON POSTs returning server errors:

```json
{
  "method": "POST",
  "statusCode": 500,
  "hasRequestBody": true,
  "contentTypeContains": "json",
  "newestFirst": true,
  "count": 10,
  "fields": ["method", "path", "host", "statusCode", "contentType", "requestContentLength"]
}
```

### `get_proxy_http_history_message_slice`

Returns a bounded slice from request or response, choosing headers, body, or full message.

Parameters:

- `index`: 1-based history index.
- `message`: `request` or `response`.
- `part`: `headers`, `body`, or `full`.
- `offset`: slice offset.
- `length`: max bytes or characters to return.

Examples:

```json
{
  "index": 42,
  "message": "request",
  "part": "headers",
  "offset": 0,
  "length": 4000
}
```

```json
{
  "index": 42,
  "message": "response",
  "part": "body",
  "offset": 0,
  "length": 8000
}
```

Prefer this over `get_proxy_http_history_body` because it can target headers, body, or full message explicitly.

### `send_http_request_from_history`

Replays a captured proxy HTTP request by 1-based index, optionally mutating path, body, and headers.

Parameters:

- `index`
- `replacePath`
- `replaceBody`
- `replaceHeaders`

Example IDOR probe:

```json
{
  "index": 42,
  "replacePath": "/api/users/124",
  "replaceHeaders": {
    "X-Burp-MCP-Probe": "idor-test"
  }
}
```

The tool uses the original captured request as the base and sends it through Burp's HTTP stack. It returns the response in serialized form.

### `send_http_request_from_history_with_diff`

Replays a captured proxy HTTP request by 1-based index, applies the same optional path, body, and header mutations, and returns compact baseline vs mutated response evidence.

Parameters:

- `index`
- `replacePath`
- `replaceBody`
- `replaceHeaders`
- `bodyPreviewLength`

Example:

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

Output includes:

- `baseline.statusCode`, `baseline.contentType`, `baseline.bodyLength`, `baseline.bodySha256`, `baseline.headerNames`
- `mutated.statusCode`, `mutated.contentType`, `mutated.bodyLength`, `mutated.bodySha256`, `mutated.headerNames`
- `delta.statusChanged`, `delta.contentTypeChanged`, `delta.bodyLengthDelta`, `delta.bodyHashChanged`, `delta.similarity`
- `delta.headerNamesAdded`, `delta.headerNamesRemoved`
- `preview.firstDifference`

Prefer this over raw replay when validating a hypothesis. It gives agents deterministic before/after evidence without dumping full bodies.

### HTTP history annotations

Use annotations to leave state for the human operator and later agents.

Tools:

- `set_proxy_http_history_note`
- `append_proxy_http_history_note`
- `set_proxy_http_history_highlight`

Note example:

```json
{
  "index": 42,
  "note": "MCP candidate: possible IDOR. Mutated /api/users/124 returned 200 with similar JSON shape."
}
```

Highlight example:

```json
{
  "index": 42,
  "highlight": "red"
}
```

Valid highlight values: `none`, `red`, `orange`, `yellow`, `green`, `cyan`, `blue`, `pink`, `magenta`, `gray`.

Suggested color convention:

- `red`: high-value or likely vulnerability
- `orange`: needs manual review
- `yellow`: suspicious but weak
- `green`: tested and likely safe
- `cyan`: auth/session behavior
- `blue`: recon or coverage marker
- `pink` or `magenta`: parser, weirdness, or error behavior
- `gray`: deprioritized

### Repeater and Intruder from history

Use these when a candidate needs manual or attack-tool follow-up:

```json
{
  "index": 42,
  "tabName": "idor candidate 42"
}
```

Tools:

- `create_repeater_tab_from_history`
- `send_to_intruder_from_history`

## WebSocket History Tools

WebSocket support is more basic than HTTP support.

Available enhanced tool:

- `get_proxy_websocket_history_count`

Existing WebSocket paginated tools support `newestFirst`:

- `get_proxy_websocket_history`
- `get_proxy_websocket_history_regex`

Do not assume WebSocket has the same structured filters, message slicing, or replay support as HTTP. That parity is future work.

## Development Workflow

### Build

```bash
./gradlew embedProxyJar
```

Expected artifact:

```text
build/libs/burp-mcp-all.jar
```

### Test

Run all tests:

```bash
./gradlew test
```

Run only tool tests:

```bash
./gradlew test --tests '*ToolsKtTest*'
```

### Verify artifact

```bash
sha256sum build/libs/burp-mcp-all.jar
jar tf build/libs/burp-mcp-all.jar | grep -E 'ToolsKt.class|mcp-proxy-all.jar'
```

The final JAR should contain both the extension classes and the embedded proxy JAR.

### Git workflow

```bash
git status --short
./gradlew test
./gradlew embedProxyJar
git add src/main/kotlin/net/portswigger/mcp/tools/Tools.kt src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt AGENTS.md SKILL.md
git commit -m "feat: describe burp mcp enhanced workflow"
git push origin main
```

Only commit generated artifacts if explicitly requested. The important deliverable for Burp installation is the local `build/libs/burp-mcp-all.jar`.

## Adding a New Tool

Follow TDD. Do not wire a tool blind.

1. Read the relevant Montoya API type and existing helper functions.
2. Add a failing test in `ToolsKtTest.kt`.
3. Add the serializable input data class near the other input classes.
4. Register the tool in `Tools.kt` with a precise description.
5. Reuse existing security gates when the tool reads history or sends traffic.
6. Reuse serialization helpers instead of hand-building ad hoc strings.
7. Run the targeted test and confirm it fails for the right reason.
8. Implement the tool.
9. Run targeted tests.
10. Run the full suite.
11. Build with `./gradlew embedProxyJar`.

Security gates matter:

- History-reading tools should check `HistoryAccessSecurity`.
- Traffic-sending tools should check `HttpRequestSecurity`.
- Config-editing tools should honor `config.configEditingTooling`.

## Agent Operating Playbooks

### Find newest interesting traffic

1. `get_proxy_http_history_count`
2. `get_latest_proxy_http_history` with compact fields.
3. `get_proxy_http_history_filtered` with method, status, body, or content-type filters.
4. For candidates, use `get_proxy_http_history_message_slice` with `part=headers` first.
5. Pull body slice only if headers show the right target.

### Validate IDOR or authz candidates

1. Find authenticated request by method, path, host, and status.
2. Slice request headers to confirm auth context and content type.
3. Replay from history with `send_http_request_from_history_with_diff` using a controlled `replacePath`, `replaceBody`, or `replaceHeaders` mutation.
4. Compare status, body length delta, body hash change, similarity, and first-difference preview.
5. If promising, append a note, set a highlight, create a Repeater tab from history, and name it after the primitive.

### Validate input handling candidates

1. Filter POST, PUT, PATCH, or GraphQL traffic with request bodies.
2. Slice request body.
3. Replay with small payload changes using `replaceBody` or `replaceHeaders`.
4. Look for differential status codes, reflected payloads, OOB triggers, or parsing errors.

### Poll for newly captured traffic

1. Call `get_proxy_http_history_count` and store the count externally.
2. After browsing or crawling, call `get_proxy_http_history_since` with `afterIndex` set to the previous count.
3. Process only new entries with compact fields.
4. Update the stored index after processing.

## Common Pitfalls

1. **Editing the proxy JAR for tool changes.** Wrong target. The stdio proxy only forwards MCP traffic. Modify the Burp extension JAR.

2. **Forgetting to reload the Burp extension.** MCP clients discover tools from the running Burp instance. Rebuilding the JAR does nothing until Burp loads the new JAR.

3. **Dumping full history.** Use compact `fields` first. Pull slices only for candidate indexes.

4. **Mixing index and offset.** Agent-facing `index` is 1-based. Pagination `offset` is 0-based.

5. **Assuming latest-first is default.** Existing paginated history tools default to oldest-first unless `newestFirst` is true. `get_latest_proxy_http_history` exists to avoid that mistake.

6. **Calling replay without checking scope.** `send_http_request_from_history` sends live HTTP traffic. Confirm target scope and mutation intent before aggressive replay or fuzz-style loops.

7. **Breaking security gates.** New tools that read history or send traffic must preserve the relevant permission checks.

8. **Returning giant bodies from new tools.** Always support bounded output or field selection for anything that can grow.

9. **Trusting stale history indexes after clearing Burp history.** Indexes refer to the current in-memory history list. If history changes drastically, recount and rediscover candidates.

10. **Assuming WebSocket parity.** HTTP history has the enhanced workflow. WebSocket is not yet equally capable.

## Verification Checklist

Before handing work back:

- [ ] New or changed tool has a failing test first.
- [ ] Tool input data class is `@Serializable`.
- [ ] Tool description is precise enough for an LLM to choose it correctly.
- [ ] History tools use compact output or bounded slices.
- [ ] Live request tools pass through request security checks.
- [ ] Targeted tests pass.
- [ ] `./gradlew test` passes.
- [ ] `./gradlew embedProxyJar` succeeds.
- [ ] `build/libs/burp-mcp-all.jar` exists.
- [ ] JAR contains `ToolsKt.class` and `mcp-proxy-all.jar`.
- [ ] Commit is pushed to `origin/main` if this is repo work.
