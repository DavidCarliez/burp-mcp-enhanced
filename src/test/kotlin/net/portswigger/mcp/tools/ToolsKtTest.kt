package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.UserApprovalHandler
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.regex.Pattern
import javax.swing.JTextArea

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()
    private val persistedConfig: PersistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
    private var historyItemCounter = 1

    init {
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedConfig, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            val httpMessage = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { httpMessage.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpResponse.response() } returns httpMessage
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            val httpMessage = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { httpMessage.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpResponse.response() } returns httpMessage
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            val httpMessage = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { httpMessage.toString() } returns "HTTP/2 200 OK"
            every { httpResponse.response() } returns httpMessage
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
        @Nested
    inner class PaginatedToolsTests {

        private fun parsedHeaders(raw: String): List<Pair<String, String>> =
            raw.lineSequence().drop(1).takeWhile { it.isNotBlank() }.mapNotNull { line ->
                val separator = line.indexOf(':')
                if (separator < 0) null else line.substring(0, separator).trim() to line.substring(separator + 1).trim()
            }.toList()

        private fun parsedHeader(raw: String, name: String): String? =
            parsedHeaders(raw).firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

        private fun parsedBody(raw: String): String {
            val crlf = raw.indexOf("\r\n\r\n")
            if (crlf >= 0) return raw.substring(crlf + 4)
            val lf = raw.indexOf("\n\n")
            return if (lf >= 0) raw.substring(lf + 2) else ""
        }

        private fun byteArrayOfLength(length: Int): ByteArray =
            mockk { every { length() } returns length }

        private fun requestMock(raw: String): HttpRequest {
            val requestLine = raw.lineSequence().first()
            val path = requestLine.split(" ").getOrNull(1) ?: "/"
            val hostHeader = parsedHeader(raw, "Host") ?: "example.test:80"

            val service = mockk<burp.api.montoya.http.HttpService>()
            every { service.host() } returns hostHeader.substringBefore(':')
            every { service.port() } returns (hostHeader.substringAfter(':', "80").toIntOrNull() ?: 80)
            every { service.secure() } returns false

            val request = mockk<HttpRequest>()
            every { request.toString() } returns raw
            every { request.bodyToString() } returns parsedBody(raw)
            every { request.body() } returns byteArrayOfLength(parsedBody(raw).toByteArray().size)
            every { request.headerValue(any()) } answers { parsedHeader(raw, firstArg()) }
            every { request.hasHeader(any<String>()) } answers { parsedHeader(raw, firstArg()) != null }
            every { request.httpService() } returns service
            every { request.url() } returns "http://$hostHeader$path"
            every { request.withPath(any()) } answers { request }
            every { request.withBody(any<String>()) } answers { request }
            every { request.withUpdatedHeader(any(), any()) } answers { request }
            every { request.withAddedHeader(any(), any()) } answers { request }
            return request
        }

        private fun responseMock(raw: String): burp.api.montoya.http.message.responses.HttpResponse {
            val status = raw.lineSequence().first().split(" ").getOrNull(1)?.toIntOrNull() ?: 200
            val response = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { response.toString() } returns raw
            every { response.statusCode() } returns status.toShort()
            every { response.bodyToString() } returns parsedBody(raw)
            every { response.body() } returns byteArrayOfLength(parsedBody(raw).toByteArray().size)
            every { response.headerValue(any()) } answers { parsedHeader(raw, firstArg()) }
            return response
        }

        private fun sendResultMock(responseText: String): burp.api.montoya.http.message.HttpRequestResponse {
            val result = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { result.response() } returns responseMock(responseText)
            return result
        }

        private fun historyItem(
            requestText: String,
            responseText: String? = null,
            notes: String? = null,
            request: HttpRequest = requestMock(requestText),
            response: burp.api.montoya.http.message.responses.HttpResponse? =
                responseText?.let { responseMock(it) },
        ): ProxyHttpRequestResponse {
            val requestLine = requestText.lineSequence().first()
            val hostHeader = parsedHeader(requestText, "Host") ?: "example.test:80"
            val path = requestLine.split(" ").getOrNull(1) ?: "/"

            val annotations = mockk<Annotations>()
            every { annotations.notes() } returns notes

            val item = mockk<ProxyHttpRequestResponse>()
            every { item.id() } returns historyItemCounter++
            every { item.method() } returns requestLine.substringBefore(' ')
            every { item.host() } returns hostHeader.substringBefore(':')
            every { item.port() } returns (hostHeader.substringAfter(':', "80").toIntOrNull() ?: 80)
            every { item.path() } returns path
            every { item.url() } returns "http://$hostHeader$path"
            every { item.request() } returns request
            every { item.response() } returns response
            every { item.annotations() } returns annotations
            every { item.mimeType() } returns burp.api.montoya.http.message.MimeType.HTML
            every { item.time() } returns ZonedDateTime.now()
            every { item.contains(any<Pattern>()) } returns false
            every { item.contains(any<String>(), any()) } returns false
            return item
        }

        private fun jsonOf(text: String) = Json.parseToJsonElement(text).jsonObject

        private fun itemsOf(envelope: kotlinx.serialization.json.JsonObject) =
            envelope.getValue("items").jsonArray.map { it.jsonObject }

        @Test
        fun `search proxy http history should report a body offset usable by the body slice`() {
            val proxy = mockk<Proxy>()
            val requestText = "GET /assets/vendor.js HTTP/1.1\r\nHost: static.localhost\r\n\r\n"
            val body = "x".repeat(500) + "AKIAQ3EXAMPLEKEY7777" + "y".repeat(500)
            val item = historyItem(requestText, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n$body")

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(item)

            runBlocking {
                val text = client.callTool(
                    "search_proxy_http_history",
                    mapOf("regex" to "AKIAQ3EXAMPLEKEY7777", "count" to 5, "offset" to 0)
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertEquals(1, envelope.getValue("totalMatches").jsonPrimitive.content.toInt())
                val row = itemsOf(envelope).single()
                assertEquals(1, row.getValue("index").jsonPrimitive.content.toInt())
                assertEquals("GET", row.getValue("method").jsonPrimitive.content)
                assertEquals("static.localhost", row.getValue("host").jsonPrimitive.content)
                assertEquals(200, row.getValue("statusCode").jsonPrimitive.content.toInt())

                val hit = row.getValue("matches").jsonArray.single().jsonObject
                assertEquals("response", hit.getValue("message").jsonPrimitive.content)
                assertEquals("body", hit.getValue("part").jsonPrimitive.content)
                assertEquals(500, hit.getValue("offset").jsonPrimitive.content.toInt())
                assertEquals(20, hit.getValue("matchLength").jsonPrimitive.content.toInt())
                assertTrue(hit.getValue("context").jsonPrimitive.content.contains("AKIAQ3EXAMPLEKEY7777"))

                val sliced = client.callTool(
                    "get_proxy_http_history_body",
                    mapOf(
                        "index" to 1,
                        "message" to "response",
                        "offset" to hit.getValue("offset").jsonPrimitive.content.toInt(),
                        "length" to hit.getValue("matchLength").jsonPrimitive.content.toInt()
                    )
                ).expectTextContent()

                assertEquals("AKIAQ3EXAMPLEKEY7777", sliced)
            }
        }

        @Test
        fun `search proxy http history should report request header offsets usable by the message slice`() {
            val proxy = mockk<Proxy>()
            val requestText = "GET /x HTTP/1.1\r\nHost: example.test\r\nX-Token: SECRET123\r\n\r\n"
            val item = historyItem(requestText, "HTTP/1.1 200 OK\r\n\r\n")

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(item)

            runBlocking {
                val row = itemsOf(
                    jsonOf(
                        client.callTool(
                            "search_proxy_http_history",
                            mapOf("regex" to "SECRET123", "count" to 5, "offset" to 0)
                        ).expectTextContent()
                    )
                ).single()

                val hit = row.getValue("matches").jsonArray.single().jsonObject
                assertEquals("request", hit.getValue("message").jsonPrimitive.content)
                assertEquals("full", hit.getValue("part").jsonPrimitive.content)

                val sliced = client.callTool(
                    "get_proxy_http_history_message_slice",
                    mapOf(
                        "index" to 1,
                        "message" to "request",
                        "part" to "full",
                        "offset" to hit.getValue("offset").jsonPrimitive.content.toInt(),
                        "length" to 9
                    )
                ).expectTextContent()

                assertEquals("SECRET123", sliced)
            }
        }

        @Test
        fun `search proxy http history should bound the context window`() {
            val proxy = mockk<Proxy>()
            val body = "0123456789NEEDLEabcdefghij"
            val item = historyItem("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n$body")

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(item)

            runBlocking {
                val hit = itemsOf(
                    jsonOf(
                        client.callTool(
                            "search_proxy_http_history",
                            mapOf("regex" to "NEEDLE", "contextChars" to 3, "count" to 5, "offset" to 0)
                        ).expectTextContent()
                    )
                ).single().getValue("matches").jsonArray.single().jsonObject

                assertEquals("789NEEDLEabc", hit.getValue("context").jsonPrimitive.content)

                val rejected = client.callTool(
                    "search_proxy_http_history",
                    mapOf("regex" to "NEEDLE", "contextChars" to 500, "count" to 5, "offset" to 0)
                ).expectTextContent()
                assertTrue(rejected.contains("contextChars must be between 0 and 200"))
            }
        }

        @Test
        fun `search proxy http history should cap matches per item`() {
            val proxy = mockk<Proxy>()
            val body = (1..5).joinToString(" ") { "needle$it" }
            val item = historyItem("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n$body")

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(item)

            runBlocking {
                val row = itemsOf(
                    jsonOf(
                        client.callTool(
                            "search_proxy_http_history",
                            mapOf("regex" to "needle", "maxPerItem" to 2, "count" to 5, "offset" to 0)
                        ).expectTextContent()
                    )
                ).single()

                assertEquals(2, row.getValue("matches").jsonArray.size)

                val rejected = client.callTool(
                    "search_proxy_http_history",
                    mapOf("regex" to "needle", "maxPerItem" to 11, "count" to 5, "offset" to 0)
                ).expectTextContent()
                assertTrue(rejected.contains("maxPerItem must be between 1 and 10"))
            }
        }

        @Test
        fun `search proxy http history should use global indices for paging`() {
            val proxy = mockk<Proxy>()
            val items = listOf(
                historyItem("GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nplain"),
                historyItem("GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nMARKER one"),
                historyItem("GET /third HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nMARKER two")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns items
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(items[1], items[2])

            runBlocking {
                val firstPage = jsonOf(
                    client.callTool(
                        "search_proxy_http_history",
                        mapOf("regex" to "MARKER", "count" to 1, "offset" to 0)
                    ).expectTextContent()
                )
                val firstRow = itemsOf(firstPage).single()

                assertEquals(2, firstPage.getValue("totalMatches").jsonPrimitive.content.toInt())
                assertEquals(true, firstPage.getValue("hasMore").jsonPrimitive.content.toBoolean())
                assertEquals(2, firstRow.getValue("index").jsonPrimitive.content.toInt())
                assertEquals("/second", firstRow.getValue("path").jsonPrimitive.content)

                val secondPage = jsonOf(
                    client.callTool(
                        "search_proxy_http_history",
                        mapOf("regex" to "MARKER", "count" to 1, "offset" to 1)
                    ).expectTextContent()
                )
                val secondRow = itemsOf(secondPage).single()

                assertEquals(false, secondPage.getValue("hasMore").jsonPrimitive.content.toBoolean())
                assertEquals(3, secondRow.getValue("index").jsonPrimitive.content.toInt())

                val newest = itemsOf(
                    jsonOf(
                        client.callTool(
                            "search_proxy_http_history",
                            mapOf("regex" to "MARKER", "count" to 1, "offset" to 0, "newestFirst" to true)
                        ).expectTextContent()
                    )
                ).single()
                assertEquals(3, newest.getValue("index").jsonPrimitive.content.toInt())
            }
        }

        @Test
        fun `search proxy http history should report zero matches`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(
                historyItem("GET /only HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nplain")
            )
            every { proxy.history(any<ProxyHistoryFilter>()) } returns emptyList()

            runBlocking {
                val text = client.callTool(
                    "search_proxy_http_history", mapOf("regex" to "ABSENT", "count" to 5, "offset" to 0)
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertEquals(0, envelope.getValue("totalMatches").jsonPrimitive.content.toInt())
                assertEquals(0, envelope.getValue("returned").jsonPrimitive.content.toInt())
                assertTrue(envelope.getValue("items").jsonArray.isEmpty())
            }
        }

        @Test
        fun `search proxy http history should flag a truncated scan`() {
            val proxy = mockk<Proxy>()
            val body = "z".repeat(3_000) + "NEEDLE"
            val item = historyItem("GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n$body")

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(item)

            runBlocking {
                val row = itemsOf(
                    jsonOf(
                        client.callTool(
                            "search_proxy_http_history",
                            mapOf("regex" to "NEEDLE", "maxScanBytes" to 1_024, "count" to 5, "offset" to 0)
                        ).expectTextContent()
                    )
                ).single()

                assertEquals(true, row.getValue("scanTruncated").jsonPrimitive.content.toBoolean())
                assertTrue(row.getValue("matches").jsonArray.isEmpty())
            }
        }

        @Test
        fun `search proxy http history should reject unknown parts`() {
            runBlocking {
                val text = client.callTool(
                    "search_proxy_http_history",
                    mapOf("regex" to "needle", "parts" to listOf("cookies"), "count" to 5, "offset" to 0)
                ).expectTextContent()

                assertTrue(text.contains("parts must be a subset of"))
            }
        }

        @Test
        fun `deadline checked text should abort a scan past its budget`() {
            assertThrows(ScanTimeout::class.java) {
                DeadlineCheckedText("abcdef", 0L).get(0)
            }

            val region = SearchRegion("response", "full", "a".repeat(100), 0, 50)
            assertThrows(ScanTimeout::class.java) {
                collectMessageMatches(listOf(region), Pattern.compile("a"), 5, 3, 1_000, 0L)
            }
        }

        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /item1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", "Item 1 notes"),
                historyItem("GET /item2 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", "Item 2 notes"),
                historyItem("GET /item3 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", "Item 3 notes")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text1 = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 2, "offset" to 0)
                ).expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))

                val text2 = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 2, "offset" to 2)
                ).expectTextContent()
                assertTrue(text2.contains("GET /item3"))

                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 2, "offset" to 3)
                )
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }

        @Test
        fun `get proxy history items carry global index id and metadata`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /first HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n", "HTTP/1.1 201 Created"),
                historyItem("POST /second HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n", "HTTP/1.1 404 Not Found")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history",
                    mapOf("count" to 2, "offset" to 1, "fields" to listOf("method", "host", "port", "path", "statusCode"))
                ).expectTextContent()

                val second = jsonOf(text)
                assertEquals(2, second.getValue("index").jsonPrimitive.content.toInt())
                assertEquals(2, second.getValue("id").jsonPrimitive.content.toInt())
                assertEquals("POST", second.getValue("method").jsonPrimitive.content)
                assertEquals("api.localhost", second.getValue("host").jsonPrimitive.content)
                assertEquals(18080, second.getValue("port").jsonPrimitive.content.toInt())
                assertEquals("/second", second.getValue("path").jsonPrimitive.content)
                assertEquals(404, second.getValue("statusCode").jsonPrimitive.content.toInt())
                assertFalse(second.containsKey("request"))
            }
        }

        @Test
        fun `get proxy history newest first keeps global indices`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /oldest HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /middle HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /newest HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history",
                    mapOf("count" to 3, "offset" to 0, "newestFirst" to true, "fields" to listOf("path"))
                ).expectTextContent()

                // The page is a "\n\n" separated list of JSON documents.
                val order = text.split("\n\n").map { jsonOf(it).getValue("index").jsonPrimitive.content.toInt() }
                assertEquals(listOf(3, 2, 1), order)
            }
        }

        @Test
        fun `get proxy history should return valid size limited JSON`() {
            val proxy = mockk<Proxy>()
            val item = historyItem(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\nX-Long: ${"\\\"😀".repeat(2_000)}",
                "HTTP/1.1 200 OK\r\n\r\n${"😀".repeat(3_000)}",
                notes = "keep me"
            )
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history",
                    mapOf("count" to 1, "offset" to 0, "fields" to listOf("request", "response", "notes"))
                ).expectTextContent()
                val json = jsonOf(text)

                assertTrue(text.length <= 5_000)
                assertEquals(setOf("index", "id", "request", "response", "notes"), json.keys)
                assertTrue(json.getValue("request").jsonPrimitive.content.endsWith("... (truncated)"))
                assertTrue(json.getValue("response").jsonPrimitive.content.endsWith("... (truncated)"))
                assertEquals("keep me", json.getValue("notes").jsonPrimitive.content)
            }
        }

        @Test
        fun `get latest proxy http history should return newest item without knowing offset`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /oldest HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /middle HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /newest HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_latest_proxy_http_history", mapOf("count" to 1, "fields" to listOf("path"))
                ).expectTextContent()
                val json = jsonOf(text)

                assertEquals(3, json.getValue("index").jsonPrimitive.content.toInt())
                assertEquals("/newest", json.getValue("path").jsonPrimitive.content)
            }
        }

        @Test
        fun `get proxy http history count should return total count`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns List(5) {
                historyItem("GET /item$it HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            }

            runBlocking {
                val text = client.callTool("get_proxy_http_history_count", mapOf()).expectTextContent()
                assertEquals("5", text)
            }
        }

        @Test
        fun `get proxy http history count should count regex matches natively`() {
            val proxy = mockk<Proxy>()
            val items = List(4) {
                historyItem("GET /item$it HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            }
            every { api.proxy() } returns proxy
            every { proxy.history() } returns items
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(items[1], items[3])

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_count", mapOf("regex" to "banking")
                ).expectTextContent()
                assertEquals("2", text)
            }
        }

        @Test
        fun `get proxy http history count should reject an invalid regex`() {
            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_count", mapOf("regex" to "(")
                ).expectTextContent()
                assertTrue(text.startsWith("Invalid regex: "))
            }
        }

        @Test
        fun `get proxy http history by index should return the selected one based item`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /item1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", "notes 1"),
                historyItem("GET /item2 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", "notes 2")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_by_index", mapOf("index" to 2, "fields" to listOf("path", "notes"))
                ).expectTextContent()
                val json = jsonOf(text)

                assertEquals(2, json.getValue("index").jsonPrimitive.content.toInt())
                assertEquals("/item2", json.getValue("path").jsonPrimitive.content)
                assertEquals("notes 2", json.getValue("notes").jsonPrimitive.content)
            }
        }

        @Test
        fun `get proxy http history by index should report a missing index`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns emptyList()

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_by_index", mapOf("index" to 4)
                ).expectTextContent()
                assertEquals("No HTTP history found at 4", text)
            }
        }

        @Test
        fun `get proxy http history regex should report global indices that by index resolves to the same item`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /plain1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /needle HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /plain2 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )
            every { proxyHistory[1].contains(any<Pattern>()) } returns true

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(proxyHistory[1])

            runBlocking {
                val regexText = client.callTool(
                    "get_proxy_http_history_regex",
                    mapOf("regex" to "needle", "count" to 10, "offset" to 0, "fields" to listOf("path"))
                ).expectTextContent()
                val regexItem = jsonOf(regexText)

                assertEquals(2, regexItem.getValue("index").jsonPrimitive.content.toInt())
                assertEquals("/needle", regexItem.getValue("path").jsonPrimitive.content)

                val byIndexText = client.callTool(
                    "get_proxy_http_history_by_index",
                    mapOf("index" to regexItem.getValue("index").jsonPrimitive.content.toInt(), "fields" to listOf("path"))
                ).expectTextContent()

                assertEquals("/needle", jsonOf(byIndexText).getValue("path").jsonPrimitive.content)
            }
        }

        @Test
        fun `get proxy http history regex should fall back to a positional scan when ids collide`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /plain1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /needle HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )
            // Every item reports the same id, so identity mapping cannot be used.
            every { proxyHistory[0].id() } returns 7
            every { proxyHistory[1].id() } returns 7
            every { proxyHistory[1].contains(any<Pattern>()) } returns true

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            every { proxy.history(any<ProxyHistoryFilter>()) } returns listOf(proxyHistory[1])

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_regex",
                    mapOf("regex" to "needle", "count" to 10, "offset" to 0, "fields" to listOf("path"))
                ).expectTextContent()

                assertEquals(2, jsonOf(text).getValue("index").jsonPrimitive.content.toInt())
            }
        }

        @Test
        fun `get proxy http history since should return entries after a known index and report the history size`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /item1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /item2 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK"),
                historyItem("GET /item3 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_since",
                    mapOf("afterIndex" to 1, "count" to 10, "fields" to listOf("path"))
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertEquals(3, envelope.getValue("historySize").jsonPrimitive.content.toInt())
                assertEquals(2, envelope.getValue("returned").jsonPrimitive.content.toInt())
                assertEquals(3, envelope.getValue("nextIndex").jsonPrimitive.content.toInt())
                assertEquals(false, envelope.getValue("hasMore").jsonPrimitive.content.toBoolean())
                assertEquals(
                    listOf("/item2", "/item3"),
                    itemsOf(envelope).map { it.getValue("path").jsonPrimitive.content }
                )
            }
        }

        @Test
        fun `get proxy http history since should flag a reset history`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem("GET /item1 HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_since", mapOf("afterIndex" to 900)
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertEquals(1, envelope.getValue("historySize").jsonPrimitive.content.toInt())
                assertEquals(0, envelope.getValue("returned").jsonPrimitive.content.toInt())
                assertEquals(true, envelope.getValue("historyReset").jsonPrimitive.content.toBoolean())
            }
        }

        @Test
        fun `get proxy http history body should return a bounded request slice`() {
            val proxy = mockk<Proxy>()
            val requestText = "POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\nabcdefghij"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem(requestText, "HTTP/1.1 200 OK\r\n\r\nresponse"))

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_body",
                    mapOf("index" to 1, "message" to "request", "offset" to 2, "length" to 4)
                ).expectTextContent()

                assertEquals("cdef", text)
            }
        }

        @Test
        fun `get proxy http history body should reject an oversized length`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_body",
                    mapOf("index" to 1, "message" to "request", "offset" to 0, "length" to 500_000)
                ).expectTextContent()

                assertTrue(text.contains("length must not exceed"))
            }
        }

        @Test
        fun `get proxy http history message slice should return headers slice`() {
            val proxy = mockk<Proxy>()
            val responseText = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n", responseText))

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_message_slice",
                    mapOf("index" to 1, "message" to "response", "part" to "headers", "offset" to 0, "length" to 5000)
                ).expectTextContent()

                assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", text)
            }
        }

        @Test
        fun `create repeater tab from history should reuse selected request`() {
            val proxy = mockk<Proxy>()
            val repeater = mockk<burp.api.montoya.repeater.Repeater>()
            every { repeater.sendToRepeater(any<HttpRequest>(), any<String>()) } just runs
            val request = requestMock("GET /reuse HTTP/1.1\r\nHost: example.test\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.repeater() } returns repeater
            every { proxy.history() } returns listOf(historyItem("GET /reuse HTTP/1.1\r\nHost: example.test\r\n\r\n", request = request))

            runBlocking {
                val text = client.callTool(
                    "create_repeater_tab_from_history", mapOf("index" to 1, "tabName" to "from history")
                ).expectTextContent()

                assertEquals("Created Repeater tab from HTTP history index 1", text)
            }

            verify(exactly = 1) { repeater.sendToRepeater(request, "from history") }
        }

        @Test
        fun `send to intruder from history should reuse selected request`() {
            val proxy = mockk<Proxy>()
            val intruder = mockk<burp.api.montoya.intruder.Intruder>()
            every { intruder.sendToIntruder(any<HttpRequest>(), any<String>()) } just runs
            val request = requestMock("GET /fuzz HTTP/1.1\r\nHost: example.test\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.intruder() } returns intruder
            every { proxy.history() } returns listOf(historyItem("GET /fuzz HTTP/1.1\r\nHost: example.test\r\n\r\n", request = request))

            runBlocking {
                val text = client.callTool(
                    "send_to_intruder_from_history", mapOf("index" to 1, "tabName" to "fuzz")
                ).expectTextContent()

                assertEquals("Sent HTTP history index 1 to Intruder", text)
            }

            verify(exactly = 1) { intruder.sendToIntruder(request, "fuzz") }
        }

        @Test
        fun `get proxy http history filtered should filter by method path status and content type`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                historyItem(
                    "GET /public/index.html HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<body>"
                ),
                historyItem(
                    "POST /api/orders HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n\r\n{}",
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
                ),
                historyItem(
                    "POST /api/orders/9 HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nboom"
                )
            )

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_filtered",
                    mapOf(
                        "method" to "POST",
                        "host" to "api.example.test",
                        "pathContains" to "/api/orders",
                        "statusCode" to 200,
                        "contentTypeContains" to "json",
                        "fields" to listOf("path")
                    )
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertEquals(1, envelope.getValue("totalMatches").jsonPrimitive.content.toInt())
                assertEquals(listOf("/api/orders"), itemsOf(envelope).map { it.getValue("path").jsonPrimitive.content })
            }
        }

        @Test
        fun `get proxy http history filtered should match the host with or without a port`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(
                historyItem("GET /one HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n", "HTTP/1.1 200 OK")
            )

            runBlocking {
                val withoutPort = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf("host" to "api.localhost", "fields" to listOf("path"))
                    ).expectTextContent()
                )
                assertEquals(1, withoutPort.getValue("totalMatches").jsonPrimitive.content.toInt())

                val withPort = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf("host" to "api.localhost:18080", "fields" to listOf("path"))
                    ).expectTextContent()
                )
                assertEquals(1, withPort.getValue("totalMatches").jsonPrimitive.content.toInt())

                val wrongPort = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf("host" to "api.localhost:9999", "fields" to listOf("path"))
                    ).expectTextContent()
                )
                assertEquals(0, wrongPort.getValue("totalMatches").jsonPrimitive.content.toInt())
            }
        }

        @Test
        fun `get proxy http history filtered should page with offset and report totals`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns (1..5).map {
                historyItem("GET /page$it HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 403 Forbidden")
            }

            runBlocking {
                val firstPage = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf("statusCode" to 403, "count" to 2, "offset" to 0, "fields" to listOf("path"))
                    ).expectTextContent()
                )
                assertEquals(5, firstPage.getValue("totalMatches").jsonPrimitive.content.toInt())
                assertEquals(2, firstPage.getValue("returned").jsonPrimitive.content.toInt())
                assertEquals(true, firstPage.getValue("hasMore").jsonPrimitive.content.toBoolean())
                assertEquals(listOf("/page1", "/page2"), itemsOf(firstPage).map { it.getValue("path").jsonPrimitive.content })

                val lastPage = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf("statusCode" to 403, "count" to 2, "offset" to 4, "fields" to listOf("path"))
                    ).expectTextContent()
                )
                assertEquals(1, lastPage.getValue("returned").jsonPrimitive.content.toInt())
                assertEquals(false, lastPage.getValue("hasMore").jsonPrimitive.content.toBoolean())
                assertEquals(listOf("/page5"), itemsOf(lastPage).map { it.getValue("path").jsonPrimitive.content })
            }
        }

        @Test
        fun `get proxy http history filtered should distinguish zero matches from end of page`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(
                historyItem("GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            )

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history_filtered", mapOf("statusCode" to 599)
                ).expectTextContent()
                val envelope = jsonOf(text)

                assertFalse(text.contains("Reached end of items"))
                assertEquals(0, envelope.getValue("totalMatches").jsonPrimitive.content.toInt())
                assertEquals(0, envelope.getValue("returned").jsonPrimitive.content.toInt())
                assertEquals(true, envelope.getValue("items").jsonArray.isEmpty())
            }
        }

        @Test
        fun `get proxy http history filtered should not materialise message text for metadata filters`() {
            val proxy = mockk<Proxy>()
            val request = requestMock("GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n")
            val response = responseMock("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(
                historyItem(
                    "GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                    request = request,
                    response = response
                )
            )

            runBlocking {
                val envelope = jsonOf(
                    client.callTool(
                        "get_proxy_http_history_filtered",
                        mapOf(
                            "method" to "GET",
                            "statusCode" to 200,
                            "contentTypeContains" to "json",
                            "fields" to listOf("method", "statusCode")
                        )
                    ).expectTextContent()
                )
                assertEquals(1, envelope.getValue("totalMatches").jsonPrimitive.content.toInt())
            }

            verify(exactly = 0) { request.toString() }
            verify(exactly = 0) { response.toString() }
            verify(exactly = 0) { request.body() }
            verify(exactly = 0) { response.body() }
        }

        @Test
        fun `send http request from history should replay mutated request`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val mutatedPath = StringBuilder()
            val request = requestMock("GET /original HTTP/1.1\r\nHost: example.test\r\n\r\n")
            every { request.withPath(any()) } answers {
                mutatedPath.append(firstArg<String>())
                request
            }
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(historyItem("GET /original HTTP/1.1\r\nHost: example.test\r\n\r\n", request = request))
            every { http.sendRequest(any()) } returns sendResultMock("HTTP/1.1 200 OK\r\n\r\nreplayed")

            runBlocking {
                val text = client.callTool(
                    "send_http_request_from_history", mapOf("index" to 1, "replacePath" to "/mutated")
                ).expectTextContent()

                assertEquals("HTTP/1.1 200 OK\r\n\r\nreplayed", text)
                assertEquals("/mutated", mutatedPath.toString())
            }

            verify(exactly = 1) { http.sendRequest(request) }
        }

        @Test
        fun `send http request from history should add a header that the request is missing`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val request = requestMock("GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(historyItem("GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n", request = request))
            every { http.sendRequest(any()) } returns sendResultMock("HTTP/1.1 200 OK\r\n\r\n{}")

            runBlocking {
                client.callTool(
                    "send_http_request_from_history",
                    mapOf("index" to 1, "replaceHeaders" to mapOf("Authorization" to "Bearer token"))
                ).expectTextContent()
            }

            verify(exactly = 1) { request.withAddedHeader("Authorization", "Bearer token") }
            verify(exactly = 0) { request.withUpdatedHeader(any(), any()) }
        }

        @Test
        fun `send http request from history should update a header that already exists`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val request = requestMock("GET /page HTTP/1.1\r\nHost: example.test\r\nUser-Agent: old\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(
                historyItem("GET /page HTTP/1.1\r\nHost: example.test\r\nUser-Agent: old\r\n\r\n", request = request)
            )
            every { http.sendRequest(any()) } returns sendResultMock("HTTP/1.1 200 OK\r\n\r\nok")

            runBlocking {
                client.callTool(
                    "send_http_request_from_history",
                    mapOf("index" to 1, "replaceHeaders" to mapOf("User-Agent" to "new"))
                ).expectTextContent()
            }

            verify(exactly = 1) { request.withUpdatedHeader("User-Agent", "new") }
            verify(exactly = 0) { request.withAddedHeader(any(), any()) }
        }

        @Test
        fun `send http request from history should pass through the request approval gate`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val request = requestMock("GET /internal HTTP/1.1\r\nHost: internal.test\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(historyItem("GET /internal HTTP/1.1\r\nHost: internal.test\r\n\r\n", request = request))
            every { persistedConfig.getBoolean("requireHttpRequestApproval") } returns true

            val originalHandler = HttpRequestSecurity.approvalHandler
            var prompted: Pair<String, Int>? = null
            HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
                override suspend fun requestApproval(
                    hostname: String,
                    port: Int,
                    config: McpConfig,
                    requestContent: String?,
                    api: MontoyaApi?
                ): Boolean {
                    prompted = hostname to port
                    return false
                }
            }

            try {
                runBlocking {
                    val text = client.callTool(
                        "send_http_request_from_history", mapOf("index" to 1)
                    ).expectTextContent()

                    assertEquals("Send HTTP request denied by Burp Suite", text)
                }

                assertEquals("internal.test" to 80, prompted)
                verify(exactly = 0) { http.sendRequest(any()) }
            } finally {
                HttpRequestSecurity.approvalHandler = originalHandler
            }
        }

        @Test
        fun `send http request from history with diff should return baseline mutated fingerprints and delta`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val request = requestMock("GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(
                historyItem(
                    "GET /api/v1/users/1 HTTP/1.1\r\nHost: api.localhost:18080\r\n\r\n",
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"unauthorized\"}",
                    request = request
                )
            )
            every { http.sendRequest(any()) } returns sendResultMock(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"name\":\"admin\"}"
            )

            runBlocking {
                val text = client.callTool(
                    "send_http_request_from_history_with_diff",
                    mapOf("index" to 1, "replaceHeaders" to mapOf("Authorization" to "Bearer token"), "bodyPreviewLength" to 40)
                ).expectTextContent()
                val json = jsonOf(text)

                assertEquals(401, json.getValue("baseline").jsonObject.getValue("statusCode").jsonPrimitive.content.toInt())
                assertEquals(200, json.getValue("mutated").jsonObject.getValue("statusCode").jsonPrimitive.content.toInt())
                val delta = json.getValue("delta").jsonObject
                assertEquals(true, delta.getValue("statusChanged").jsonPrimitive.content.toBoolean())
                assertTrue(delta.getValue("similarity").jsonPrimitive.content.toDouble() < 1.0)
                assertTrue(json.getValue("preview").jsonObject.containsKey("firstDifference"))
            }
        }

        @Test
        fun `replay responses should be truncated with the original length`() {
            val proxy = mockk<Proxy>()
            val http = mockk<Http>()
            val request = requestMock("GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n")
            every { api.proxy() } returns proxy
            every { api.http() } returns http
            every { proxy.history() } returns listOf(historyItem("GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n", request = request))
            every { http.sendRequest(any()) } returns sendResultMock("HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(MAX_RESPONSE_TEXT_LENGTH + 10))

            runBlocking {
                val text = client.callTool(
                    "send_http_request_from_history", mapOf("index" to 1)
                ).expectTextContent()

                assertTrue(text.contains("... (truncated: response was ${MAX_RESPONSE_TEXT_LENGTH + 29} characters)"))
                assertTrue(text.length < MAX_RESPONSE_TEXT_LENGTH + 120)
            }
        }

        @Test
        fun `set proxy http history note should update annotations`() {
            val proxy = mockk<Proxy>()
            val annotations = mockk<Annotations>()
            val item = historyItem("GET /note HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            every { item.annotations() } returns annotations
            every { annotations.setNotes(any()) } just runs

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)

            runBlocking {
                val text = client.callTool(
                    "set_proxy_http_history_note", mapOf("index" to 1, "note" to "checked")
                ).expectTextContent()

                assertEquals("Set note on HTTP history index 1", text)
            }

            verify(exactly = 1) { annotations.setNotes("checked") }
        }

        @Test
        fun `append proxy http history note should preserve existing notes`() {
            val proxy = mockk<Proxy>()
            val annotations = mockk<Annotations>()
            val item = historyItem("GET /note HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK", notes = "existing")
            every { item.annotations() } returns annotations
            every { annotations.notes() } returns "existing"
            every { annotations.setNotes(any()) } just runs

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)

            runBlocking {
                val text = client.callTool(
                    "append_proxy_http_history_note", mapOf("index" to 1, "note" to "appended")
                ).expectTextContent()

                assertEquals("Appended note on HTTP history index 1", text)
            }

            verify(exactly = 1) { annotations.setNotes("existing\nappended") }
        }

        @Test
        fun `set proxy http history highlight should update highlight color`() {
            val proxy = mockk<Proxy>()
            val annotations = mockk<Annotations>()
            val item = historyItem("GET /highlight HTTP/1.1\r\nHost: example.test\r\n\r\n", "HTTP/1.1 200 OK")
            every { item.annotations() } returns annotations
            every { annotations.setHighlightColor(any()) } just runs

            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)

            runBlocking {
                val text = client.callTool(
                    "set_proxy_http_history_highlight", mapOf("index" to 1, "highlight" to "red")
                ).expectTextContent()

                assertEquals("Set highlight red on HTTP history index 1", text)
            }

            verify(exactly = 1) { annotations.setHighlightColor(HighlightColor.RED) }
        }
    }
    
    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}
