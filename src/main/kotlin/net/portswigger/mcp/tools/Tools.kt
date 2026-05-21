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
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.KeyboardFocusManager
import java.security.MessageDigest
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun firstLine(message: String?): String? {
    return message?.lineSequence()?.firstOrNull()
}

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

private fun requestMethod(request: String?): String? = firstLine(request)?.split(" ")?.getOrNull(0)

private fun requestPath(request: String?): String? = firstLine(request)?.split(" ")?.getOrNull(1)

private fun statusCode(response: String?): Int? = firstLine(response)?.split(" ")?.getOrNull(1)?.toIntOrNull()

private fun contentType(request: String?, response: String?): String? =
    headerValue(response, "Content-Type") ?: headerValue(request, "Content-Type")

private fun serializeHttpHistoryItem(
    index: Int,
    item: ProxyHttpRequestResponse,
    fields: List<String>? = null,
): String {
    val serializableItem = item.toSerializableForm()
    val selectedFields = fields?.filter { it.isNotBlank() }?.toSet().takeUnless { it.isNullOrEmpty() }
    val itemJson = if (selectedFields == null) {
        Json.encodeToJsonElement(serializableItem)
    } else {
        buildJsonObject {
            val requestBody = bodyPart(serializableItem.request)
            val responseBody = bodyPart(serializableItem.response)
            if ("request" in selectedFields) put("request", serializableItem.request?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("response" in selectedFields) put("response", serializableItem.response?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("notes" in selectedFields) put("notes", serializableItem.notes?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("requestLine" in selectedFields) put("requestLine", firstLine(serializableItem.request)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("responseLine" in selectedFields) put("responseLine", firstLine(serializableItem.response)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("method" in selectedFields) put("method", requestMethod(serializableItem.request)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("path" in selectedFields) put("path", requestPath(serializableItem.request)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("host" in selectedFields) put("host", headerValue(serializableItem.request, "Host")?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("statusCode" in selectedFields) put("statusCode", statusCode(serializableItem.response)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("contentType" in selectedFields) put("contentType", contentType(serializableItem.request, serializableItem.response)?.let { JsonPrimitive(it) } ?: JsonNull)
            if ("requestContentLength" in selectedFields) put("requestContentLength", requestBody.length)
            if ("responseContentLength" in selectedFields) put("responseContentLength", responseBody.length)
            if ("hasRequestBody" in selectedFields) put("hasRequestBody", requestBody.isNotEmpty())
            if ("hasResponseBody" in selectedFields) put("hasResponseBody", responseBody.isNotEmpty())
        }
    }
    return truncateIfNeeded(Json.encodeToString(buildJsonObject {
        put("index", index)
        put("item", itemJson)
    }))
}

private fun sliceBody(message: String, offset: Int, length: Int): String {
    val safeOffset = offset.coerceAtLeast(0)
    val safeLength = length.coerceAtLeast(0)
    if (safeOffset >= message.length || safeLength == 0) return ""
    return message.substring(safeOffset, (safeOffset + safeLength).coerceAtMost(message.length))
}

private fun sliceMessage(message: String, part: String, offset: Int, length: Int): String {
    val selected = when (part.lowercase()) {
        "headers" -> headerPart(message)
        "body" -> bodyPart(message)
        "full" -> message
        else -> return "part must be 'headers', 'body', or 'full'"
    }
    return sliceBody(selected, offset, length)
}

private fun historyItemMatches(
    item: ProxyHttpRequestResponse,
    method: String?,
    host: String?,
    pathContains: String?,
    statusCodeFilter: Int?,
    hasRequestBodyFilter: Boolean?,
    hasResponseBodyFilter: Boolean?,
    contentTypeContains: String?,
): Boolean {
    val serializableItem = item.toSerializableForm()
    val requestBody = bodyPart(serializableItem.request)
    val responseBody = bodyPart(serializableItem.response)
    return (method == null || requestMethod(serializableItem.request)?.equals(method, ignoreCase = true) == true) &&
        (host == null || headerValue(serializableItem.request, "Host")?.equals(host, ignoreCase = true) == true) &&
        (pathContains == null || requestPath(serializableItem.request)?.contains(pathContains, ignoreCase = true) == true) &&
        (statusCodeFilter == null || statusCode(serializableItem.response) == statusCodeFilter) &&
        (hasRequestBodyFilter == null || requestBody.isNotEmpty() == hasRequestBodyFilter) &&
        (hasResponseBodyFilter == null || responseBody.isNotEmpty() == hasResponseBodyFilter) &&
        (contentTypeContains == null || contentType(serializableItem.request, serializableItem.response)?.contains(contentTypeContains, ignoreCase = true) == true)
}

private fun applyHistoryRequestMutation(
    originalRequest: HttpRequest,
    replacePath: String?,
    replaceBody: String?,
    replaceHeaders: Map<String, String>?,
): HttpRequest {
    var request = originalRequest
    if (replacePath != null) request = request.withPath(replacePath)
    if (replaceBody != null) request = request.withBody(replaceBody)
    replaceHeaders?.forEach { (name, value) ->
        request = request.withUpdatedHeader(name, value)
    }
    return request
}

private fun sha256Hex(value: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}

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

private fun responseFingerprint(message: String?): JsonObject {
    val body = bodyPart(message)
    return buildJsonObject {
        put("statusCode", statusCode(message)?.let { JsonPrimitive(it) } ?: JsonNull)
        put("contentType", headerValue(message, "Content-Type")?.let { JsonPrimitive(it) } ?: JsonNull)
        put("bodyLength", body.length)
        put("bodySha256", sha256Hex(body))
        putJsonArray("headerNames") {
            headerNames(message).sorted().forEach { add(it) }
        }
    }
}

private fun responseSimilarity(left: String, right: String): Double {
    if (left == right) return 1.0
    val maxLength = maxOf(left.length, right.length)
    if (maxLength == 0) return 1.0
    val commonPrefix = left.zip(right).takeWhile { it.first == it.second }.count()
    return commonPrefix.toDouble() / maxLength.toDouble()
}

private fun firstDifferencePreview(left: String, right: String, previewLength: Int): JsonObject {
    val safeLength = previewLength.coerceAtLeast(0)
    val diffIndex = left.zip(right).indexOfFirst { it.first != it.second }.let { index ->
        when {
            index >= 0 -> index
            left.length != right.length -> minOf(left.length, right.length)
            else -> -1
        }
    }
    return buildJsonObject {
        if (diffIndex < 0 || safeLength == 0) {
            put("offset", if (diffIndex < 0) JsonNull else JsonPrimitive(diffIndex))
            put("baseline", "")
            put("mutated", "")
        } else {
            val start = (diffIndex - safeLength / 4).coerceAtLeast(0)
            put("offset", diffIndex)
            put("baseline", sliceBody(left, start, safeLength))
            put("mutated", sliceBody(right, start, safeLength))
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
    return Json.encodeToString(buildJsonObject {
        put("baseline", responseFingerprint(baseline))
        put("mutated", responseFingerprint(mutated))
        putJsonObject("delta") {
            put("statusChanged", statusCode(baseline) != statusCode(mutated))
            put("contentTypeChanged", headerValue(baseline, "Content-Type") != headerValue(mutated, "Content-Type"))
            put("bodyLengthDelta", mutatedBody.length - baselineBody.length)
            put("bodyHashChanged", sha256Hex(baselineBody) != sha256Hex(mutatedBody))
            put("similarity", responseSimilarity(baselineBody, mutatedBody))
            putJsonArray("headerNamesAdded") {
                (mutatedHeaders - baselineHeaders).sorted().forEach { add(it) }
            }
            putJsonArray("headerNamesRemoved") {
                (baselineHeaders - mutatedHeaders).sorted().forEach { add(it) }
            }
        }
        putJsonObject("preview") {
            put("firstDifference", firstDifferencePreview(baselineBody, mutatedBody, bodyPreviewLength))
        }
    })
}

private fun parseHighlightColor(highlight: String): HighlightColor? {
    return runCatching { HighlightColor.valueOf(highlight.trim().uppercase()) }.getOrNull()
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
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

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

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

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
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
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
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
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
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

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val history = api.proxy().history()
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence().mapIndexed { pageIndex, item ->
            val originalIndex = if (newestFirst) history.size - pageIndex else pageIndex + 1
            serializeHttpHistoryItem(originalIndex, item, fields)
        }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        val history = api.proxy().history { it.contains(compiledRegex) }
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence().mapIndexed { pageIndex, item ->
            val originalIndex = if (newestFirst) history.size - pageIndex else pageIndex + 1
            serializeHttpHistoryItem(originalIndex, item, fields)
        }
    }

    mcpTool<GetProxyHttpHistoryCount>("Returns the total number of items in the proxy HTTP history, optionally filtered by regex") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history count")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = if (regex != null) {
            val compiledRegex = Pattern.compile(regex)
            api.proxy().history { it.contains(compiledRegex) }
        } else {
            api.proxy().history()
        }
        history.size.toString()
    }

    mcpTool<GetLatestProxyHttpHistory>("Displays the latest items from the proxy HTTP history without requiring the caller to know the final offset") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "latest HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        if (history.isEmpty()) {
            "Reached end of items"
        } else {
            history.asReversed().take(count).mapIndexed { pageIndex, item ->
                serializeHttpHistoryItem(history.size - pageIndex, item, fields)
            }.joinToString(separator = "\n\n")
        }
    }

    mcpTool<GetProxyHttpHistoryByIndex>("Displays a single item within the proxy HTTP history by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history by index")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
        if (requestResponse == null) {
            "No HTTP history found at $index"
        } else {
            serializeHttpHistoryItem(index, requestResponse, fields)
        }
    }

    mcpTool<GetProxyHttpHistorySince>("Displays HTTP history items added after a known 1-based index, optionally with compact fields") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history since index")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        val startIndex = afterIndex.coerceAtLeast(0)
        if (startIndex >= history.size) {
            "Reached end of items"
        } else {
            history.drop(startIndex).take(count).mapIndexed { pageIndex, item ->
                serializeHttpHistoryItem(startIndex + pageIndex + 1, item, fields)
            }.joinToString(separator = "\n\n")
        }
    }

    mcpTool<GetProxyHttpHistoryBody>("Returns a bounded body slice from a proxy HTTP history request or response by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history body")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        val serializableItem = requestResponse.toSerializableForm()
        val selectedMessage = when (message.lowercase()) {
            "request" -> serializableItem.request
            "response" -> serializableItem.response
            else -> return@mcpTool "message must be 'request' or 'response'"
        }
        sliceBody(bodyPart(selectedMessage), offset, length)
    }

    mcpTool<GetProxyHttpHistoryMessageSlice>("Returns a bounded headers, body, or full-message slice from a proxy HTTP history request or response by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history message slice")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val requestResponse = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        val serializableItem = requestResponse.toSerializableForm()
        val selectedMessage = when (message.lowercase()) {
            "request" -> serializableItem.request
            "response" -> serializableItem.response
            else -> return@mcpTool "message must be 'request' or 'response'"
        } ?: ""
        sliceMessage(selectedMessage, part, offset, length)
    }

    mcpTool<GetProxyHttpHistoryFiltered>("Displays proxy HTTP history items filtered by structured request and response metadata") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "filtered HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        val indexedHistory = history.mapIndexed { pageIndex, item -> pageIndex + 1 to item }
        val ordered = if (newestFirst) indexedHistory.asReversed() else indexedHistory
        val matches = ordered.asSequence()
            .filter { (_, item) -> historyItemMatches(item, method, host, pathContains, statusCode, hasRequestBody, hasResponseBody, contentTypeContains) }
            .take(count)
            .map { (historyIndex, item) -> serializeHttpHistoryItem(historyIndex, item, fields) }
            .toList()

        if (matches.isEmpty()) "Reached end of items" else matches.joinToString(separator = "\n\n")
    }

    mcpTool<SendHttpRequestFromHistory>("Replays a proxy HTTP history request by 1-based index with optional path, body, and header mutations") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "replay HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val originalRequest = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        val request = applyHistoryRequestMutation(originalRequest, replacePath, replaceBody, replaceHeaders)
        api.http().sendRequest(request)?.toString() ?: "<no response>"
    }

    mcpTool<SendHttpRequestFromHistoryWithDiff>("Replays a proxy HTTP history request by 1-based index and returns compact baseline vs mutated response fingerprints, deltas, and first-difference preview") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "replay HTTP history with diff")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP request found at history index $index"
        val baselineResponse = historyItem.toSerializableForm().response
        val request = applyHistoryRequestMutation(historyItem.request(), replacePath, replaceBody, replaceHeaders)
        val mutatedResponse = api.http().sendRequest(request)?.toString()
            ?: return@mcpTool "<no response>"
        responseDiffJson(baselineResponse, mutatedResponse, bodyPreviewLength)
    }

    mcpTool<SetProxyHttpHistoryNote>("Sets the note for a proxy HTTP history item by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "set HTTP history note")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val historyItem = api.proxy().history().getOrNull(index - 1)
            ?: return@mcpTool "No HTTP history found at $index"
        historyItem.annotations().setNotes(note)
        "Set note on HTTP history index $index"
    }

    mcpTool<AppendProxyHttpHistoryNote>("Appends a line to the note for a proxy HTTP history item by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "append HTTP history note")
        }
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

    mcpTool<SetProxyHttpHistoryHighlight>("Sets the highlight color for a proxy HTTP history item by 1-based index. Valid colors: none, red, orange, yellow, green, cyan, blue, pink, magenta, gray") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "set HTTP history highlight")
        }
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

    mcpTool<CreateRepeaterTabFromHistory>("Creates a Repeater tab from a proxy HTTP history item by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "create Repeater tab from HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val request = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        api.repeater().sendToRepeater(request, tabName)
        "Created Repeater tab from HTTP history index $index"
    }

    mcpTool<SendToIntruderFromHistory>("Sends a proxy HTTP history request to Intruder by 1-based index") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "send HTTP history to Intruder")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val request = api.proxy().history().getOrNull(index - 1)?.request()
            ?: return@mcpTool "No HTTP request found at history index $index"
        api.intruder().sendToIntruder(request, tabName)
        "Sent HTTP history index $index to Intruder"
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val history = api.proxy().webSocketHistory()
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        val history = api.proxy().webSocketHistory { it.contains(compiledRegex) }
        val ordered = if (newestFirst) history.asReversed() else history
        ordered.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<GetProxyWebsocketHistoryCount>("Returns the total number of items in the proxy WebSocket history, optionally filtered by regex") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history count")
        }
        if (!allowed) {
            return@mcpTool "WebSocket history access denied by Burp Suite"
        }

        val history = if (regex != null) {
            val compiledRegex = Pattern.compile(regex)
            api.proxy().webSocketHistory { it.contains(compiledRegex) }
        } else {
            api.proxy().webSocketHistory()
        }
        history.size.toString()
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