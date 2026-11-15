# Burp MCP Enhanced

**A drop-in replacement for PortSwigger's Burp Suite MCP server, rebuilt for agents that actually have to read proxy history.**

[![CI](https://github.com/DavidCarliez/burp-mcp-enhanced/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidCarliez/burp-mcp-enhanced/actions/workflows/ci.yml)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2026.10.x-orange)
![Version](https://img.shields.io/badge/version-1.3.0--enhanced.2-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

Upstream `mcp-server` 1.3.0, plus 16 tools and a reworked history model: global indexes, server-side counts, newest-first paging, regex search that returns the hit with context, structured filtering with totals, character-range slices, replay with mutation and diff, and annotations. Same extension, same SSE port, same approvals, same hardening. Just usable at 20,000 requests.

---

## The problem

The official Burp MCP server cannot answer "give me the newest request" without paging the entire history. In a benchmark on a 20,001-request history, that task cost **31 offset probes**, and in one of three agent runs the agent confidently reported the *oldest* request as the newest because it gave up before reaching the end. Counting 554 admin 403s meant paging every match: **270 KB of output**. Reading 2 KB from the middle of a 1.3 MB response was impossible, and a regex hit 80 KB into a JavaScript bundle was invisible behind a hard `substring(0, 5000)` cap.

Those are not Burp limitations. They are thin tool definitions that never expose what Burp already knows.

## The numbers

Benchmark: 14 scripted tasks and 18 headless Claude Code runs (6 tasks × 3 runs) over a deterministic 20,001-request corpus, summed per server. Full methodology, harness and raw results: [**DavidCarliez/proxy-mcp-bench**](https://github.com/DavidCarliez/proxy-mcp-bench).

| 14 scripted tasks | Correct | Tool calls | Output returned to the model |
|---|---:|---:|---:|
| PortSwigger `mcp-server` 1.3.0 | 11 / 14 | 58 | 6.6 MB |
| **burp-mcp-enhanced 1.3.0-enhanced.2** | **14 / 14** | **27** | **48.1 KB** |

| 18 agent runs (Sonnet) | Correct | Time | Tokens | Cost |
|---|---:|---:|---:|---:|
| PortSwigger `mcp-server` 1.3.0 | 14 / 18 | 247 s | 5.58 M | $2.74 |
| **burp-mcp-enhanced 1.3.0-enhanced.2** | **18 / 18** | **90 s** | **0.46 M** | **$0.44** |

**137× less tool output, 2.7× faster, 12× fewer tokens, 6.2× cheaper, every task correct.** Per-task detail in the grid below; the benchmark's companion write-up is [*Your MCP Server Is Slowing Your Pentest Agent Down*](https://dc-cybersec.com/blog/agentic-pentesting-mcp-benchmark/).

![Tool calls and bytes returned to the model per task, official vs enhanced](https://raw.githubusercontent.com/DavidCarliez/proxy-mcp-bench/main/figures/task-grid.svg)

Four cases worth naming, because they are the shape of a real engagement:

| Question at 20k requests | Official | Enhanced |
|---|---|---|
| Newest request | 31 calls, 3.9 s, 1 wrong answer in 3 agent runs | 1 call, 0.02 s |
| Count admin-host 403s | 69.5 s, 20 calls, 1.07 M tokens | 10.8 s, 2 calls, 67 K tokens |
| Requests per host | **failed 3/3**, 92.5 s and $1.73 per run | correct 3/3 |
| Find an AWS key deep in a JS bundle | truncated away, needed a refetch | 1 call, 706 bytes, key visible at offset 79,810 |

Cost no longer grows with the history:

![Tool calls and bytes from 20k to 100k requests](https://raw.githubusercontent.com/DavidCarliez/proxy-mcp-bench/main/figures/scale.svg)

At 100,005 requests, the Caido upstream server needed 1,001 calls (10 MB) to find the newest request; Burp offset probing rose from 3.9 s to 21.7 s of wall time; counting 403s grew from 270 KB to 1.35 MB on Burp and from 54 KB to 271 KB on Caido. **This fork stays at one call and under 1 KB at every size.**

---

## What this fork adds

16 new tools, all of them pointing at things Burp already exposes. `index` is a **global 1-based position** shared by every tool below: a regex hit at index 41 can be passed unchanged to a slice, a replay or a Repeater handoff. Every HTTP history row also carries Burp's native `id`.

### Navigation and counting

| Tool | Why it exists |
|---|---|
| `get_proxy_http_history_count` | "How many" without listing them. Optional `regex` counts matching *items*, not occurrences. |
| `get_latest_proxy_http_history` | Newest entries without computing an offset. Replaces the probe loop that produced wrong answers. |
| `get_proxy_http_history_by_index` | Fetch exactly one item by global index. |
| `get_proxy_http_history_since` | Poll after a cursor: returns `nextIndex`, `hasMore` and `historyReset` so a stale cursor is detected, not silently reused. |
| `get_proxy_websocket_history_count` | Same count primitive for WebSocket history. |

### Search and triage

| Tool | Why it exists |
|---|---|
| `search_proxy_http_history` | Returns each regex hit with its **global index, character offset and context** (40 chars each side by default, 200 max). Never dumps a message. Byte and 5-second caps return a partial page instead of hanging the extension. |
| `get_proxy_http_history_filtered` | Metadata-only filtering on method, host (with or without port), path substring, status, body presence and content type. Returns `totalMatches`, `offset`, `hasMore` — **no totals-by-paging**. |
| `fields` on every HTTP list tool | Allowlist of item keys; `index` and `id` are always present. Without `fields` every key is emitted, bodies included, so a broad scan can be made to cost status + path only. |
| `newestFirst` on every list, plus `time`, `mimeType` and `notes` as selectable item keys | Warm-start in a live engagement without an offset trick. |

### Reading without dumping

| Tool | Why it exists |
|---|---|
| `get_proxy_http_history_message_slice` | `headers`, `body` or `full`, at a character offset, up to 200,000 chars. This is what makes 1.3 MB responses and 150 KB bundles readable. |
| `get_proxy_http_history_body` | Body-only convenience path. |
| Bounded output everywhere | `count` ≤ 500, slices ≤ 200,000 chars, one history item ≤ 5,000 chars of **still-valid JSON** with `... (truncated)` markers, send/replay responses ≤ 200,000 chars. A missing request/response is `null`, never placeholder text. |

### Acting on what you found

| Tool | Why it exists |
|---|---|
| `send_http_request_from_history` | Replay a captured request with `replacePath`, `replaceBody`, `replaceHeaders`. Headers are **added when absent**, so `Authorization` and `Cookie` injection works. |
| `send_http_request_from_history_with_diff` | Baseline vs mutated: status, content type, length, SHA-256, similarity, header deltas, and the first differing body offset. Deterministic evidence for IDOR/authz triage without dumping bodies. |
| `set_proxy_http_history_note`, `append_proxy_http_history_note` | Leave state for the next agent or the human operator. |
| `set_proxy_http_history_highlight` | Ten colors for triage state, e.g. red = likely vulnerability, green = tested safe. |
| `create_repeater_tab_from_history`, `send_to_intruder_from_history` | Escalate a candidate, named after the primitive it tests. |

### Kept from upstream, unchanged

27 upstream tools, the SSE server on `127.0.0.1:9876`, the stdio proxy, the Claude Desktop installer, and the whole security model: per-target approval gates, cancellable approvals, credential redaction in config export, JSON-preserving truncation, prelude-only request normalization, HTTP/2 Repeater tabs and Organizer tools.

---

## Three bugs this fork had to fix first

Two results went the wrong way in the first round. The recorded traces, plus a review against upstream, turned up three bugs in the fork:

- **Regex hits were renumbered.** Hits reported their position inside the *filtered list*, so "find, then read" opened the wrong request. Now every hit carries the global index.
- **Replay dropped injected headers.** `replaceHeaders` only replaced existing keys; an added `Authorization` vanished. Now it adds.
- **Replay skipped approvals.** Replayed traffic now goes through the same per-target gate as `send_http1_request`, evaluated against the mutated target, and inherits the auto-approve list.

After those fixes, finding the leaked key went from **62.8 s / 19 calls / 186 KB** (fork, 1.3.0-enhanced.1) and **32.4 s / 6 calls / 11.9 KB** (official) to **14.8 s / 3 calls / 1.1 KB** — with `search_proxy_http_history` in 1.3.0-enhanced.2.

---

## Install

Requires Java 21 and the `jar` tool on `PATH`.

```bash
git clone https://github.com/DavidCarliez/burp-mcp-enhanced.git
cd burp-mcp-enhanced
./gradlew embedProxyJar
```

Load `build/libs/burp-mcp-all.jar` in **Burp → Extensions → Add → Java**. Enable the server in the **MCP** tab. Clients connect to `http://127.0.0.1:9876` (SSE), or use the bundled stdio proxy:

```bash
java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

`serverInfo` reports `1.3.0-enhanced.2`, so you can tell which build an MCP client is actually talking to.

## Use

Agent-facing contracts, pitfalls and worked playbooks live in [`SKILL.md`](SKILL.md) and [`AGENTS.md`](AGENTS.md). The short version:

1. `get_proxy_http_history_count`
2. `get_latest_proxy_http_history` with compact `fields`
3. `get_proxy_http_history_filtered` on the shape you want
4. `get_proxy_http_history_message_slice` for headers, then body, of candidates only
5. `send_http_request_from_history_with_diff` to prove a hypothesis
6. Note, highlight, Repeater, Intruder

Prompts that now work in one or two calls:

```
What is the newest request in my proxy history?
How many requests to admin.localhost got a 403?
Find the AWS-style access key in the history and show me 80 characters around it.
Replay request 4123 with /api/users/124 and tell me what changed in the body.
Show me the last 20 requests to admin.localhost that returned 500.
```

## Limits, stated plainly

- Tool definitions cost context: 43 tools ≈ **4,300 tokens per turn** versus 27 tools ≈ 2,100 upstream. Prompt caching softens it, and both are far below the 20,700 tokens a Caido MCP setup pays, but it is a real trade.
- The benchmark is loopback, synthetic traffic, one model, three runs per task. Directional, not a statistical study.
- WebSocket history has counts and `newestFirst`, not full parity with HTTP slices and replay.
- Burp approval dialogs still apply. They are answered before unattended runs, because a dialog nobody clicks is a hung agent.
- `index` refers to the current in-memory history. After a clear, recount; `get_proxy_http_history_since` reports `historyReset` instead of lying.

## Compatibility

Forked from `PortSwigger/mcp-server` at `v1.3.0`; upstream history is preserved, so rebasing onto later releases is a normal merge. Drop-in: no client changes, no new ports, no config migration. Built and tested against Burp Suite Professional 2026.10.1 on Montoya API 2025.10, the version upstream `v1.3.0` pins.

## Credits

Upstream extension: [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) (GPL-3.0). Benchmark, harness and figures: [DavidCarliez/proxy-mcp-bench](https://github.com/DavidCarliez/proxy-mcp-bench). Written up in [*Your MCP Server Is Slowing Your Pentest Agent Down*](https://dc-cybersec.com/blog/agentic-pentesting-mcp-benchmark/).
