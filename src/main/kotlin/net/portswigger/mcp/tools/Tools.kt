package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.limitHistoryItemElement
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.security.MessageDigest
import java.util.regex.Pattern
import javax.swing.JTextArea

/**
 * Hard limits for tool output. Every paged, sliced or previewed result is bounded so a single call
 * cannot flood the caller's context; exceeding a limit is reported as an explicit error instead of
 * being silently applied.
 */
internal const val MAX_PAGE_COUNT = 500
internal const val MAX_SLICE_LENGTH = 200_000
internal const val MAX_BODY_PREVIEW_LENGTH = 20_000
internal const val MAX_RESPONSE_TEXT_LENGTH = 200_000

private const val MIN_PAGE_COUNT = 1

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

// ---------------------------------------------------------------------------
// Raw message helpers. These operate on message text, never on a whole history.
// ---------------------------------------------------------------------------

private fun firstLine(message: String?): String? = message?.lineSequence()?.firstOrNull()

private fun headerPart(message: String?): String {
    if (message == null) return ""
    val crlfBodyIndex = message.indexOf("\r\n\r\n")
    if (crlfBodyIndex >= 0) return message.substring(0, crlfBodyIndex)

    val lfBodyIndex = message.indexOf("\n\n")
    if (lfBodyIndex >= 0) return message.substring(0, lfBodyIndex)

    return message
}

private fun bodyPart(message: String?): String {
    if (message == null) return ""
    val crlfBodyIndex = message.indexOf("\r\n\r\n")
    if (crlfBodyIndex >= 0) return message.substring(crlfBodyIndex + 4)

    val lfBodyIndex = message.indexOf("\n\n")
    if (lfBodyIndex >= 0) return message.substring(lfBodyIndex + 2)

    return ""
}

/** Offset of the body inside the raw message, i.e. where `bodyPart` starts. */
private fun bodyOffset(message: String?): Int {
    if (message == null) return 0
    val crlfBodyIndex = message.indexOf("\r\n\r\n")
    if (crlfBodyIndex >= 0) return crlfBodyIndex + 4

    val lfBodyIndex = message.indexOf("\n\n")
    if (lfBodyIndex >= 0) return lfBodyIndex + 2

    return message.length
}

private fun headerValue(message: String?, name: String): String? {
    return headerPart(message).lineSequence()
        .drop(1)
        .mapNotNull { line ->
            val separator = line.indexOf(':')
            if (separator < 0) null else line.substring(0, separator).trim() to line.substring(separator + 1).trim()
        }
        .firstOrNull { it.first.equals(name, ignoreCase = true) }
        ?.second
}

private fun responseStatusFromText(message: String?): Int? =
    firstLine(message)?.split(" ")?.getOrNull(1)?.toIntOrNull()

private fun headerNames(message: String?): Set<String> {
    return headerPart(message).lineSequence()
        .drop(1)
        .mapNotNull { line ->
            val separator = line.indexOf(':')
            if (separator < 0) null else line.substring(0, separator).trim()
        }
        .filter { it.isNotBlank() }
        .toSet()
}

/**
 * Length of the message body in bytes. Uses the declared `Content-Length` header when present so a
 * metadata query never has to copy the body; only chunked/undeclared bodies fall back to the byte
 * copy, because Montoya exposes no lazy body length.
 */
internal fun HttpMessage.bodyLength(): Int {
    val declared = headerValue("Content-Length")?.trim()?.toIntOrNull()
    if (declared != null) return declared.coerceAtLeast(0)
    return body().length()
}

// ---------------------------------------------------------------------------
// Slicing
// ---------------------------------------------------------------------------

internal fun sliceRange(text: String, offset: Int, length: Int): String {
    val safeOffset = offset.coerceAtLeast(0)
    val safeLength = length.coerceAtLeast(0)
    if (safeOffset >= text.length || safeLength == 0) return ""
    return text.substring(safeOffset, (safeOffset + safeLength).coerceAtMost(text.length))
}

internal fun sliceMessageText(message: String, part: String, offset: Int, length: Int): String {
    val selected = when (part.lowercase()) {
        "headers" -> headerPart(message)
        "body" -> bodyPart(message)
        "full" -> message
        else -> return "part must be 'headers', 'body', or 'full'"
    }
    return sliceRange(selected, offset, length)
}

/** Body slice of a raw message, addressed by 0-based character offset into the body. */
internal fun bodySlice(message: String, offset: Int, length: Int): String =
    sliceRange(bodyPart(message), offset, length)

// ---------------------------------------------------------------------------
// Response diff helpers
// ---------------------------------------------------------------------------

internal fun commonPrefixLength(left: String, right: String): Int {
    val limit = minOf(left.length, right.length)
    var index = 0
    while (index < limit && left[index] == right[index]) index++
    return index
}

/** Index of the first differing character, or the shared length when one string is a prefix of the other. */
internal fun firstDifferenceIndex(left: String, right: String): Int {
    val prefix = commonPrefixLength(left, right)
    return if (prefix < left.length || prefix < right.length) prefix else -1
}

private fun sha256Hex(value: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}

private fun responseFingerprint(message: String?): JsonObject {
    val body = bodyPart(message)
    return buildJsonObject {
        put("statusCode", responseStatusFromText(message)?.let { JsonPrimitive(it) } ?: JsonNull)
        put("contentType", headerValue(message, "Content-Type")?.let { JsonPrimitive(it) } ?: JsonNull)
        put("bodyLength", body.length)
        put("bodySha256", sha256Hex(body))
        putJsonArray("headerNames") { headerNames(message).sorted().forEach { add(JsonPrimitive(it)) } }
    }
}

private fun responseSimilarity(left: String, right: String): Double {
    if (left == right) return 1.0
    val maxLength = maxOf(left.length, right.length)
    if (maxLength == 0) return 1.0
    return commonPrefixLength(left, right).toDouble() / maxLength.toDouble()
}

/**
 * Locates the first difference between two response bodies.
 *
 * Offsets are reported at three granularities so the returned window can be fed straight back into
 * `get_proxy_http_history_message_slice`: `previewStart` and `bodyOffset` are relative to the body
 * (use them with `part="body"`), `messageOffset` is relative to the whole baseline message (use it
 * with `part="full"`).
 */
internal fun firstDifferencePreview(
    baselineBody: String, mutatedBody: String, previewLength: Int, baselineBodyOffset: Int
): JsonObject {
    val safeLength = previewLength.coerceAtLeast(0)
    val diffIndex = firstDifferenceIndex(baselineBody, mutatedBody)
    return buildJsonObject {
        if (diffIndex < 0 || safeLength == 0) {
            put("bodyOffset", if (diffIndex < 0) JsonNull else JsonPrimitive(diffIndex))
            put("messageOffset", if (diffIndex < 0) JsonNull else JsonPrimitive(baselineBodyOffset + diffIndex))
            put("previewStart", JsonNull)
            put("baseline", "")
            put("mutated", "")
        } else {
            val start = (diffIndex - safeLength / 4).coerceAtLeast(0)
            put("bodyOffset", diffIndex)
            put("messageOffset", baselineBodyOffset + diffIndex)
            put("previewStart", start)
            put("baseline", sliceRange(baselineBody, start, safeLength))
            put("mutated", sliceRange(mutatedBody, start, safeLength))
        }
    }
}

private fun responseDiffJson(baselineResponse: String?, mutatedResponse: String?, bodyPreviewLength: Int): String {
    val baseline = baselineResponse ?: ""
    val mutated = mutatedResponse ?: ""
    val baselineBody = bodyPart(baseline)
    val mutatedBody = bodyPart(mutated)
    val baselineHeaders = headerNames(baseline)
    val mutatedHeaders = headerNames(mutated)
    return buildJsonObject {
        put("baseline", responseFingerprint(baseline))
        put("mutated", responseFingerprint(mutated))
        putJsonObject("delta") {
            put("statusChanged", responseStatusFromText(baseline) != responseStatusFromText(mutated))
            put("contentTypeChanged", headerValue(baseline, "Content-Type") != headerValue(mutated, "Content-Type"))
            put("bodyLengthDelta", mutatedBody.length - baselineBody.length)
            put("bodyHashChanged", sha256Hex(baselineBody) != sha256Hex(mutatedBody))
            put("similarity", responseSimilarity(baselineBody, mutatedBody))
            putJsonArray("headerNamesAdded") { (mutatedHeaders - baselineHeaders).sorted().forEach { add(JsonPrimitive(it)) } }
            putJsonArray("headerNamesRemoved") { (baselineHeaders - mutatedHeaders).sorted().forEach { add(JsonPrimitive(it)) } }
        }
        putJsonObject("preview") {
            put("firstDifference", firstDifferencePreview(baselineBody, mutatedBody, bodyPreviewLength, bodyOffset(baseline)))
        }
    }.toString()
}

// ---------------------------------------------------------------------------
// History metadata and serialization
// ---------------------------------------------------------------------------

/**
 * Metadata of one proxy history item, read exclusively through Montoya accessors. Building this
 * never touches request/response message text.
 */
internal data class HistoryItemMetadata(
    val index: Int,
    val id: Int,
    val method: String,
    val host: String,
    val port: Int,
    val path: String,
    val url: String,
    val statusCode: Int?,
    val mimeType: String,
    val time: String,
)

internal fun ProxyHttpRequestResponse.historyMetadata(index: Int): HistoryItemMetadata = HistoryItemMetadata(
    index = index,
    id = id(),
    method = method(),
    host = host(),
    port = port(),
    path = path(),
    url = url(),
    statusCode = response()?.statusCode()?.toInt(),
    mimeType = mimeType().name,
    time = time().toString(),
)

private val DEFAULT_HISTORY_FIELDS = listOf(
    "method", "host", "port", "path", "url", "time", "mimeType", "statusCode",
    "requestContentLength", "responseContentLength", "notes", "request", "response",
)

/**
 * Serializes one history item to JSON.
 *
 * `index` and `id` are always present: `index` is the 1-based position in the unfiltered proxy
 * history (the address every index-based tool uses) and `id` is Burp's own item id. Any other key
 * is expensive to produce, so it is only emitted when selected through `fields`; without `fields`
 * every key is emitted.
 *
 * A missing request or response is emitted as JSON `null` rather than as a placeholder string, so
 * no synthetic text can ever be confused with stored message content.
 */
internal fun historyItemJson(
    index: Int,
    item: ProxyHttpRequestResponse,
    fields: List<String>?,
): JsonObject {
    val metadata = item.historyMetadata(index)
    val selected = fields?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet().takeUnless { it.isNullOrEmpty() }
    fun wanted(name: String) = selected == null || name in selected

    return buildJsonObject {
        put("index", metadata.index)
        put("id", metadata.id)
        if (wanted("method")) put("method", metadata.method)
        if (wanted("host")) put("host", metadata.host)
        if (wanted("port")) put("port", metadata.port)
        if (wanted("path")) put("path", metadata.path)
        if (wanted("url")) put("url", metadata.url)
        if (wanted("time")) put("time", metadata.time)
        if (wanted("mimeType")) put("mimeType", metadata.mimeType)
        if (wanted("statusCode")) put("statusCode", metadata.statusCode?.let { JsonPrimitive(it) } ?: JsonNull)
        if (wanted("requestContentLength")) put("requestContentLength", item.request()?.bodyLength() ?: 0)
        if (wanted("responseContentLength")) put("responseContentLength", item.response()?.bodyLength() ?: 0)
        if (wanted("notes")) put("notes", item.annotations().notes()?.let { JsonPrimitive(it) } ?: JsonNull)
        if (wanted("request")) put("request", item.request()?.toString()?.let { JsonPrimitive(it) } ?: JsonNull)
        if (wanted("response")) put("response", item.response()?.toString()?.let { JsonPrimitive(it) } ?: JsonNull)
    }
}

internal fun serializeHistoryItem(
    index: Int,
    item: ProxyHttpRequestResponse,
    fields: List<String>?,
): String = encodeHistoryItem(historyItemJson(index, item, fields))

private fun serializeHistoryItemElement(
    index: Int,
    item: ProxyHttpRequestResponse,
    fields: List<String>?,
): JsonObject = limitHistoryItemElement(historyItemJson(index, item, fields)) as JsonObject

internal fun websocketItemJson(index: Int, item: ProxyWebSocketMessage): JsonObject =
    buildJsonObject {
        put("index", index)
        put("id", item.id())
        put("time", item.time().toString())
        put("direction", item.direction().name)
        put("length", item.payload().length())
        put("notes", item.annotations().notes()?.let { JsonPrimitive(it) } ?: JsonNull)
        put("payload", item.payload().toString())
    }

private fun serializeWebSocketItem(index: Int, item: ProxyWebSocketMessage): String =
    encodeHistoryItem(websocketItemJson(index, item))

// ---------------------------------------------------------------------------
// History filtering
// ---------------------------------------------------------------------------

internal data class HistoryFilter(
    val method: String? = null,
    val host: String? = null,
    val pathContains: String? = null,
    val statusCode: Int? = null,
    val hasRequestBody: Boolean? = null,
    val hasResponseBody: Boolean? = null,
    val contentTypeContains: String? = null,
)

/**
 * Matches a history item against a structured filter using Montoya metadata only: no request or
 * response text is materialised, so this stays cheap even on a 20k item history.
 */
internal fun historyItemMatches(item: ProxyHttpRequestResponse, filter: HistoryFilter): Boolean {
    if (filter.method != null && !item.method().equals(filter.method, ignoreCase = true)) return false
    if (filter.host != null && !historyHostMatches(item, filter.host)) return false
    if (filter.pathContains != null && !item.path().contains(filter.pathContains, ignoreCase = true)) return false
    if (filter.statusCode != null && item.response()?.statusCode()?.toInt() != filter.statusCode) return false
    if (filter.contentTypeContains != null && !historyContentTypeMatches(item, filter.contentTypeContains)) return false
    if (filter.hasRequestBody != null && (item.request()?.bodyLength() ?: 0 > 0) != filter.hasRequestBody) return false
    if (filter.hasResponseBody != null && (item.response()?.bodyLength() ?: 0 > 0) != filter.hasResponseBody) return false
    return true
}

/** Accepts a host with or without its port, with or without a scheme. */
internal fun historyHostMatches(item: ProxyHttpRequestResponse, hostFilter: String): Boolean {
    val wanted = hostFilter.trim().removePrefix("https://").removePrefix("http://").trimEnd('/')
    if (wanted.isEmpty()) return true
    val host = item.host()
    val withPort = "$host:${item.port()}"
    return wanted.equals(host, ignoreCase = true) || wanted.equals(withPort, ignoreCase = true)
}

private fun historyContentTypeMatches(item: ProxyHttpRequestResponse, filter: String): Boolean {
    if (item.mimeType().name.contains(filter, ignoreCase = true)) return true
    val declared = item.response()?.headerValue("Content-Type") ?: item.request()?.headerValue("Content-Type")
    return declared?.contains(filter, ignoreCase = true) == true
}

// ---------------------------------------------------------------------------
// Index resolution
// ---------------------------------------------------------------------------

/**
 * Result of a native regex scan, addressed by global history position.
 *
 * `items` is the full history snapshot the indices refer to; `indices` are 1-based positions into
 * it, ascending.
 */
internal class HistoryMatches(
    val items: List<ProxyHttpRequestResponse>,
    val indices: List<Int>,
)

/**
 * Runs Burp's native `contains(Pattern)` scan and maps the matches back onto global history
 * positions, so a regex hit can be passed to any index-based tool unchanged.
 *
 * The native scan is used because it searches request and response bytes inside Burp without
 * marshalling them across the API. Mapping is done on `id()`; if that turns out not to be a stable
 * identity for the current Burp build, a positional scan is used instead so the result is always
 * correct.
 */
internal fun findHistoryMatches(api: MontoyaApi, pattern: Pattern): HistoryMatches {
    val matched = api.proxy().history { it.contains(pattern) }
    if (matched.isEmpty()) return HistoryMatches(emptyList(), emptyList())

    val snapshot = api.proxy().history()
    val matchedIds = HashSet<Int>(matched.size * 2)
    for (item in matched) matchedIds.add(item.id())

    val identityUsable = matchedIds.size == matched.size
    if (identityUsable) {
        val indices = ArrayList<Int>(matchedIds.size)
        snapshot.forEachIndexed { position, item ->
            if (item.id() in matchedIds) indices.add(position + 1)
        }
        if (indices.size == matched.size) return HistoryMatches(snapshot, indices)
    }

    val indices = ArrayList<Int>(matched.size)
    snapshot.forEachIndexed { position, item ->
        if (item.contains(pattern)) indices.add(position + 1)
    }
    return HistoryMatches(snapshot, indices)
}

// ---------------------------------------------------------------------------
// Request mutation
// ---------------------------------------------------------------------------

/**
 * Applies replay mutations to a stored request. Headers that already exist are updated; headers
 * that the request does not carry are added, so an injected `Authorization`/`Cookie` actually
 * reaches the target.
 */
internal fun applyHistoryRequestMutation(
    originalRequest: HttpRequest,
    replacePath: String?,
    replaceBody: String?,
    replaceHeaders: Map<String, String>?,
): HttpRequest {
    var request = originalRequest
    if (replacePath != null) request = request.withPath(replacePath)
    if (replaceBody != null) request = request.withBody(replaceBody)
    replaceHeaders?.forEach { (name, value) ->
        request = if (request.hasHeader(name)) {
            request.withUpdatedHeader(name, value)
        } else {
            request.withAddedHeader(name, value)
        }
    }
    return request
}

/** Resolves the `host:port` a request would be sent to, falling back to the Host header. */
internal fun requestTarget(request: HttpRequest): Pair<String, Int> {
    val service: HttpService? = request.httpService()
    if (service != null) return service.host() to service.port()

    val text = request.toString()
    val declared = headerValue(text, "Host") ?: return "" to 0
    val host = declared.substringBefore(":")
    val port = declared.substringAfter(":", "").toIntOrNull()
        ?: if (headerValue(text, "Host") != null && request.url().startsWith("https://", ignoreCase = true)) 443 else 80
    return host to port
}

// ---------------------------------------------------------------------------
// Output envelope helpers
// ---------------------------------------------------------------------------

private fun countLimitError(count: Int): String? = when {
    count < MIN_PAGE_COUNT -> "count must be at least $MIN_PAGE_COUNT"
    count > MAX_PAGE_COUNT -> "count must not exceed $MAX_PAGE_COUNT"
    else -> null
}

private fun lengthLimitError(length: Int): String? = when {
    length < 0 -> "length must not be negative"
    length > MAX_SLICE_LENGTH -> "length must not exceed $MAX_SLICE_LENGTH"
    else -> null
}

private fun boundedResponseText(response: String?): String {
    if (response == null) return "<no response>"
    if (response.length <= MAX_RESPONSE_TEXT_LENGTH) return response
    return response.substring(0, MAX_RESPONSE_TEXT_LENGTH) +
        "\n\n... (truncated: response was ${response.length} characters)"
}

private fun parseHighlightColor(highlight: String): HighlightColor? {
    return runCatching { HighlightColor.valueOf(highlight.trim().uppercase()) }.getOrNull()
}

private const val REGEX_ERROR_PREFIX = "Invalid regex: "

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendRequest(request)

        boundedResponseText(response?.response()?.toString())
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        boundedResponseText(response?.response()?.toString())
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options. Credential values are redacted unless the user turns filtering off."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options. Credential values are redacted unless the user turns filtering off."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
                "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
                "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
                "Optionally filter by payloadId from generate_collaborator_payload. " +
                "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>(
        "Displays items within the proxy HTTP history. Each item is JSON carrying its global 1-based 'index' and Burp 'id'. Use 'fields' to select keys and 'newestFirst' to page from the end."
    ) {
        countLimitError(count)?.let { return@mcpPaginatedTool sequenceOf(it) }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val history = api.proxy().history()
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence().mapIndexed { pageIndex, item ->
            val originalIndex = if (newestFirst) history.size - pageIndex else pageIndex + 1
            serializeHistoryItem(originalIndex, item, fields)
        }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Displays items matching a specified regex within the proxy HTTP history. Burp performs the scan over request and response bytes. Every item carries its global 1-based 'index', so it can be passed straight to _by_index, _body, _message_slice and the replay tools."
    ) {
        countLimitError(count)?.let { return@mcpPaginatedTool sequenceOf(it) }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val pattern = runCatching { Pattern.compile(regex) }.getOrNull()
            ?: return@mcpPaginatedTool sequenceOf("$REGEX_ERROR_PREFIX$regex")

        val matches = findHistoryMatches(api, pattern)
        val ordered = if (newestFirst) matches.indices.asReversed() else matches.indices
        ordered.asSequence().map { index -> serializeHistoryItem(index, matches.items[index - 1], fields) }
    }

    mcpTool<GetProxyHttpHistoryCount>(
        "Returns the total number of proxy HTTP history items, optionally those matching a regex. The regex count is the number of items containing a match, not the number of matches. Montoya exposes no count primitive, so this always builds the history snapshot (O(items), no message text)."
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history count")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        if (regex == null) {
            api.proxy().history().size.toString()
        } else {
            val pattern = runCatching { Pattern.compile(regex) }.getOrNull()
                ?: return@mcpTool "$REGEX_ERROR_PREFIX$regex"
            api.proxy().history { it.contains(pattern) }.size.toString()
        }
    }

    mcpTool<GetLatestProxyHttpHistory>(
        "Displays the latest items from the proxy HTTP history without requiring the caller to know the final offset. Items carry their global 1-based index."
    ) {
        countLimitError(count)?.let { return@mcpTool it }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "latest HTTP history")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        if (history.isEmpty()) {
            "Reached end of items"
        } else {
            history.asReversed().take(count).mapIndexed { pageIndex, item ->
                serializeHistoryItem(history.size - pageIndex, item, fields)
            }.joinToString(separator = "\n\n")
        }
    }

    mcpTool<GetProxyHttpHistoryByIndex>(
        "Displays a single item within the proxy HTTP history by its global 1-based index, optionally with compact fields."
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history by index")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
        if (requestResponse == null) {
            "No HTTP history found at $index"
        } else {
            serializeHistoryItem(index, requestResponse, fields)
        }
    }

    mcpTool<GetProxyHttpHistorySince>(
        "Displays HTTP history items after a known global 1-based index, optionally with compact fields. Also reports the current history size, so a caller can tell an empty tail from a cleared or reset history."
    ) {
        countLimitError(count)?.let { return@mcpTool it }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history since index")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        val startIndex = afterIndex.coerceAtLeast(0)
        val page = if (startIndex >= history.size) {
            emptyList()
        } else {
            history.drop(startIndex).take(count)
        }

        buildJsonObject {
            put("historySize", history.size)
            put("afterIndex", startIndex)
            put("returned", page.size)
            put("nextIndex", startIndex + page.size)
            put("hasMore", startIndex + page.size < history.size)
            put("historyReset", history.size < startIndex)
            put("items", buildJsonArray {
                page.forEachIndexed { pageIndex, item ->
                    add(serializeHistoryItemElement(startIndex + pageIndex + 1, item, fields))
                }
            })
        }.toString()
    }

    mcpTool<GetProxyHttpHistoryBody>(
        "Returns a bounded body slice from a proxy HTTP history request or response by global 1-based index. Offsets and lengths are characters of the body. An empty result means the offset is past the end."
    ) {
        lengthLimitError(length)?.let { return@mcpTool it }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history body")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        val selectedMessage = when (message.lowercase()) {
            "request" -> requestResponse.request()?.bodyToString()
            "response" -> requestResponse.response()?.bodyToString()
            else -> return@mcpTool "message must be 'request' or 'response'"
        } ?: ""

        sliceRange(selectedMessage, offset, length)
    }

    mcpTool<GetProxyHttpHistoryMessageSlice>(
        "Returns a bounded headers, body, or full-message slice from a proxy HTTP history request or response by global 1-based index. Offsets and lengths are characters."
    ) {
        lengthLimitError(length)?.let { return@mcpTool it }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history message slice")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        if (part.lowercase() !in setOf("headers", "body", "full")) {
            return@mcpTool "part must be 'headers', 'body', or 'full'"
        }
        val selectedMessage = when (message.lowercase()) {
            "request" -> requestResponse.request()?.toString()
            "response" -> requestResponse.response()?.toString()
            else -> return@mcpTool "message must be 'request' or 'response'"
        } ?: ""

        sliceMessageText(selectedMessage, part, offset, length)
    }

    mcpTool<GetProxyHttpHistoryFiltered>(
        "Filters proxy HTTP history items on Montoya metadata (method, host, path, status, content type, body presence). The host may be given with or without its port. Results are returned newest-first or oldest-first with 'offset'/'count' paging, and the envelope always reports 'totalMatches' and 'hasMore' so a zero-match filter is never confused with the end of a page."
    ) {
        countLimitError(count)?.let { return@mcpTool it }
        if (offset < 0) return@mcpTool "offset must not be negative"

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "filtered HTTP history")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val filter = HistoryFilter(
            method = method,
            host = host,
            pathContains = pathContains,
            statusCode = statusCode,
            hasRequestBody = hasRequestBody,
            hasResponseBody = hasResponseBody,
            contentTypeContains = contentTypeContains,
        )

        val history = api.proxy().history()
        val matchedIndices = ArrayList<Int>()
        history.forEachIndexed { position, item ->
            if (historyItemMatches(item, filter)) matchedIndices.add(position + 1)
        }

        val ordered = if (newestFirst) matchedIndices.asReversed() else matchedIndices
        val page = ordered.drop(offset).take(count)

        buildJsonObject {
            put("totalMatches", matchedIndices.size)
            put("offset", offset)
            put("returned", page.size)
            put("hasMore", offset + page.size < matchedIndices.size)
            put("items", buildJsonArray {
                page.forEach { historyIndex ->
                    add(serializeHistoryItemElement(historyIndex, history[historyIndex - 1], fields))
                }
            })
        }.toString()
    }

    mcpTool<SendHttpRequestFromHistory>(
        "Replays a proxy HTTP history request by global 1-based index with optional path, body, and header mutations. Headers listed in replaceHeaders are updated when present and added when absent. Replay goes through the same per-target approval gate as send_http1_request."
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "replay HTTP history")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val originalRequest = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        val request = applyHistoryRequestMutation(originalRequest, replacePath, replaceBody, replaceHeaders)

        val target = requestTarget(request)
        val authorized = HttpRequestSecurity.checkHttpRequestPermission(
            target.first, target.second, config, request.toString(), api
        )
        if (!authorized) {
            api.logging().logToOutput("MCP history replay denied: ${target.first}:${target.second}")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP history replay: ${target.first}:${target.second}")
        currentCoroutineContext().ensureActive()
        boundedResponseText(api.http().sendRequest(request)?.response()?.toString())
    }

    mcpTool<SendHttpRequestFromHistoryWithDiff>(
        "Replays a proxy HTTP history request by global 1-based index and returns compact baseline vs mutated response fingerprints, deltas, and first-difference preview. Replay goes through the same per-target approval gate as send_http1_request."
    ) {
        lengthLimitError(bodyPreviewLength)?.let { return@mcpTool it }

        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "replay HTTP history with diff")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP request found at history index $index"
        val request = applyHistoryRequestMutation(historyItem.request(), replacePath, replaceBody, replaceHeaders)

        val target = requestTarget(request)
        val authorized = HttpRequestSecurity.checkHttpRequestPermission(
            target.first, target.second, config, request.toString(), api
        )
        if (!authorized) {
            api.logging().logToOutput("MCP history replay denied: ${target.first}:${target.second}")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        val baselineResponse = historyItem.response()?.toString()
        api.logging().logToOutput("MCP history replay with diff: ${target.first}:${target.second}")
        currentCoroutineContext().ensureActive()
        val mutatedResponse = api.http().sendRequest(request)?.response()?.toString()
            ?: return@mcpTool "<no response>"
        responseDiffJson(baselineResponse, mutatedResponse, bodyPreviewLength)
    }

    mcpTool<SetProxyHttpHistoryNote>("Sets the note for a proxy HTTP history item by global 1-based index") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "set HTTP history note")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        historyItem.annotations().setNotes(note)
        "Set note on HTTP history index $index"
    }

    mcpTool<AppendProxyHttpHistoryNote>("Appends a line to the note for a proxy HTTP history item by global 1-based index") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "append HTTP history note")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        val annotations = historyItem.annotations()
        val existing = annotations.notes().takeUnless { it.isNullOrBlank() }
        annotations.setNotes(listOfNotNull(existing, note).joinToString("\n"))
        "Appended note on HTTP history index $index"
    }

    mcpTool<SetProxyHttpHistoryHighlight>("Sets the highlight color for a proxy HTTP history item by global 1-based index. Valid colors: none, red, orange, yellow, green, cyan, blue, pink, magenta, gray") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "set HTTP history highlight")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val color = parseHighlightColor(highlight)
            ?: return@mcpTool "highlight must be one of: none, red, orange, yellow, green, cyan, blue, pink, magenta, gray"
        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        historyItem.annotations().setHighlightColor(color)
        "Set highlight ${highlight.lowercase()} on HTTP history index $index"
    }

    mcpTool<CreateRepeaterTabFromHistory>("Creates a Repeater tab from a proxy HTTP history item by global 1-based index") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "create Repeater tab from HTTP history")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val request = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        api.repeater().sendToRepeater(request, tabName)
        "Created Repeater tab from HTTP history index $index"
    }

    mcpTool<SendToIntruderFromHistory>("Sends a proxy HTTP history request to Intruder by global 1-based index") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "send HTTP history to Intruder")
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val request = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        api.intruder().sendToIntruder(request, tabName)
        "Sent HTTP history index $index to Intruder"
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val pattern = runCatching { Pattern.compile(regex) }.getOrNull()
            ?: return@mcpPaginatedTool sequenceOf("$REGEX_ERROR_PREFIX$regex")
        api.organizer().items { it.contains(pattern) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>(
        "Displays items within the proxy WebSocket history. Each item is one frame; 'index' is its global 1-based frame position."
    ) {
        countLimitError(count)?.let { return@mcpPaginatedTool sequenceOf(it) }

        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val history = api.proxy().webSocketHistory()
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence().mapIndexed { pageIndex, item ->
            val originalIndex = if (newestFirst) history.size - pageIndex else pageIndex + 1
            serializeWebSocketItem(originalIndex, item)
        }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>(
        "Displays items matching a specified regex within the proxy WebSocket history. Each item is one frame."
    ) {
        countLimitError(count)?.let { return@mcpPaginatedTool sequenceOf(it) }

        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val pattern = runCatching { Pattern.compile(regex) }.getOrNull()
            ?: return@mcpPaginatedTool sequenceOf("$REGEX_ERROR_PREFIX$regex")
        val matched = api.proxy().webSocketHistory { it.contains(pattern) }
        val ordered = if (newestFirst) matched.asReversed() else matched
        ordered.asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<GetProxyWebsocketHistoryCount>(
        "Returns the number of WebSocket history frames, optionally those matching a regex. Frames are counted one by one, so the number is not comparable with HTTP request/response items."
    ) {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history count")
        if (!allowed) {
            return@mcpTool "WebSocket history access denied by Burp Suite"
        }

        if (regex == null) {
            api.proxy().webSocketHistory().size.toString()
        } else {
            val pattern = runCatching { Pattern.compile(regex) }.getOrNull()
                ?: return@mcpTool "$REGEX_ERROR_PREFIX$regex"
            api.proxy().webSocketHistory { it.contains(pattern) }.size.toString()
        }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(
    override val count: Int,
    override val offset: Int,
    val newestFirst: Boolean = false,
    val fields: List<String>? = null,
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val newestFirst: Boolean = false,
    val fields: List<String>? = null,
) : Paginated

@Serializable
data class GetProxyHttpHistoryCount(val regex: String? = null)

@Serializable
data class GetLatestProxyHttpHistory(val count: Int = 1, val fields: List<String>? = null)

@Serializable
data class GetProxyHttpHistoryByIndex(val index: Int, val fields: List<String>? = null)

@Serializable
data class GetProxyHttpHistorySince(val afterIndex: Int, val count: Int = 10, val fields: List<String>? = null)

@Serializable
data class GetProxyHttpHistoryBody(val index: Int, val message: String, val offset: Int = 0, val length: Int = 5000)

@Serializable
data class GetProxyHttpHistoryMessageSlice(
    val index: Int,
    val message: String,
    val part: String = "body",
    val offset: Int = 0,
    val length: Int = 5000,
)

@Serializable
data class GetProxyHttpHistoryFiltered(
    val method: String? = null,
    val host: String? = null,
    val pathContains: String? = null,
    val statusCode: Int? = null,
    val hasRequestBody: Boolean? = null,
    val hasResponseBody: Boolean? = null,
    val contentTypeContains: String? = null,
    val newestFirst: Boolean = false,
    val offset: Int = 0,
    val count: Int = 10,
    val fields: List<String>? = null,
)

@Serializable
data class SendHttpRequestFromHistory(
    val index: Int,
    val replacePath: String? = null,
    val replaceBody: String? = null,
    val replaceHeaders: Map<String, String>? = null,
)

@Serializable
data class SendHttpRequestFromHistoryWithDiff(
    val index: Int,
    val replacePath: String? = null,
    val replaceBody: String? = null,
    val replaceHeaders: Map<String, String>? = null,
    val bodyPreviewLength: Int = 1000,
)

@Serializable
data class SetProxyHttpHistoryNote(val index: Int, val note: String)

@Serializable
data class AppendProxyHttpHistoryNote(val index: Int, val note: String)

@Serializable
data class SetProxyHttpHistoryHighlight(val index: Int, val highlight: String)

@Serializable
data class CreateRepeaterTabFromHistory(val index: Int, val tabName: String? = null)

@Serializable
data class SendToIntruderFromHistory(val index: Int, val tabName: String? = null)

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int, val newestFirst: Boolean = false) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int, val newestFirst: Boolean = false) :
    Paginated

@Serializable
data class GetProxyWebsocketHistoryCount(val regex: String? = null)

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
