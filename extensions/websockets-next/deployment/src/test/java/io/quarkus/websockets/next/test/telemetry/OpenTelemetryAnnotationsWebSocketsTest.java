package io.quarkus.websockets.next.test.telemetry;

import static io.opentelemetry.semconv.UrlAttributes.URL_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import jakarta.inject.Inject;

import org.awaitility.Awaitility;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.netty.handler.codec.http.websocketx.WebSocketCloseStatus;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.quarkus.builder.Version;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.websockets.next.OnClose;
import io.quarkus.websockets.next.OnOpen;
import io.quarkus.websockets.next.OnTextMessage;
import io.quarkus.websockets.next.WebSocket;
import io.quarkus.websockets.next.WebSocketClient;
import io.quarkus.websockets.next.WebSocketConnection;
import io.quarkus.websockets.next.WebSocketConnector;
import io.quarkus.websockets.next.test.utils.WSClient;
import io.vertx.core.Vertx;
import io.vertx.core.http.WebSocketConnectOptions;

public class OpenTelemetryAnnotationsWebSocketsTest {

    @RegisterExtension
    public static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot(root -> root
                    .addClasses(OtelBounceEndpoint.class, WSClient.class, InMemorySpanExporterProducer.class,
                            OtelBounceClient.class)
                    .addAsResource(new StringAsset("""
                            quarkus.otel.bsp.export.timeout=1s
                            quarkus.otel.bsp.schedule.delay=50
                            """), "application.properties"))
            .setForcedDependencies(
                    List.of(Dependency.of("io.quarkus", "quarkus-opentelemetry-deployment", Version.getVersion())));

    @TestHTTPResource("bounce")
    URI bounceUri;

    @TestHTTPResource("/")
    URI baseUri;

    @Inject
    Vertx vertx;

    @Inject
    InMemorySpanExporter spanExporter;

    @Inject
    WebSocketConnector<OtelBounceClient> connector;

    @BeforeEach
    public void resetSpans() {
        spanExporter.reset();
        OtelBounceEndpoint.connectionId = null;
        OtelBounceEndpoint.endpointId = null;
        OtelBounceEndpoint.MESSAGES.clear();
        OtelBounceClient.MESSAGES.clear();
        OtelBounceClient.CLOSED_LATCH = new CountDownLatch(1);
        OtelBounceEndpoint.CLOSED_LATCH = new CountDownLatch(1);
    }

    @Test
    public void testServerEndpointTracesOnly() {
        assertEquals(0, spanExporter.getFinishedSpanItems().size());
        try (WSClient client = new WSClient(vertx)) {
            client.connect(new WebSocketConnectOptions(), bounceUri);
            var response = client.sendAndAwaitReply("How U Livin'").toString();
            assertEquals("How U Livin'", response);
        }
        waitForTracesToArrive(3);
        var initialRequestSpan = getSpanByName("GET /bounce", SpanKind.SERVER);

        var connectionOpenedSpan = getSpanByName("OPEN " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionOpenedSpan));
        assertEquals(initialRequestSpan.getSpanId(), connectionOpenedSpan.getLinks().get(0).getSpanContext().getSpanId());

        var connectionClosedSpan = getSpanByName("CLOSE " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.connectionId, getConnectionIdAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.endpointId, getEndpointIdAttrVal(connectionClosedSpan));
        assertEquals(1, connectionClosedSpan.getLinks().size());
        assertEquals(connectionOpenedSpan.getSpanId(), connectionClosedSpan.getLinks().get(0).getSpanContext().getSpanId());
    }

    @Test
    public void testClientAndServerEndpointTraces() throws InterruptedException {
        var clientConn = connector.baseUri(baseUri).connectAndAwait();
        clientConn.sendTextAndAwait("Make It Bun Dem");

        // assert client and server called
        Awaitility.await().untilAsserted(() -> {
            assertEquals(1, OtelBounceEndpoint.MESSAGES.size());
            assertEquals("Make It Bun Dem", OtelBounceEndpoint.MESSAGES.get(0));
            assertEquals(1, OtelBounceClient.MESSAGES.size());
            assertEquals("Make It Bun Dem", OtelBounceClient.MESSAGES.get(0));
        });

        clientConn.closeAndAwait();
        // assert connection closed and client/server were notified
        assertTrue(OtelBounceClient.CLOSED_LATCH.await(5, TimeUnit.SECONDS));
        assertTrue(OtelBounceEndpoint.CLOSED_LATCH.await(5, TimeUnit.SECONDS));

        waitForTracesToArrive(5);

        // server traces
        var initialRequestSpan = getSpanByName("GET /bounce", SpanKind.SERVER);
        var connectionOpenedSpan = getSpanByName("OPEN " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionOpenedSpan));
        assertEquals(initialRequestSpan.getSpanId(), connectionOpenedSpan.getLinks().get(0).getSpanContext().getSpanId());
        var connectionClosedSpan = getSpanByName("CLOSE " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.connectionId, getConnectionIdAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.endpointId, getEndpointIdAttrVal(connectionClosedSpan));
        assertEquals(1, connectionClosedSpan.getLinks().size());
        assertEquals(connectionOpenedSpan.getSpanId(), connectionClosedSpan.getLinks().get(0).getSpanContext().getSpanId());

        // client traces
        connectionOpenedSpan = getSpanByName("OPEN " + bounceUri.getPath(), SpanKind.CLIENT);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionOpenedSpan));
        assertTrue(connectionOpenedSpan.getLinks().isEmpty());
        connectionClosedSpan = getSpanByName("CLOSE " + bounceUri.getPath(), SpanKind.CLIENT);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionClosedSpan));
        assertNotNull(getConnectionIdAttrVal(connectionClosedSpan));
        assertNotNull(getClientIdAttrVal(connectionClosedSpan));
        assertEquals(1, connectionClosedSpan.getLinks().size());
        assertEquals(connectionOpenedSpan.getSpanId(), connectionClosedSpan.getLinks().get(0).getSpanContext().getSpanId());
    }

    @Test
    public void testServerTracesWhenErrorOnMessage() {
        assertEquals(0, spanExporter.getFinishedSpanItems().size());
        try (WSClient client = new WSClient(vertx)) {
            client.connect(new WebSocketConnectOptions(), bounceUri);
            var response = client.sendAndAwaitReply("It's Alright, Ma").toString();
            assertEquals("It's Alright, Ma", response);
            response = client.sendAndAwaitReply("I'm Only Bleeding").toString();
            assertEquals("I'm Only Bleeding", response);

            client.sendAndAwait("throw-exception");
            Awaitility.await().atMost(Duration.ofSeconds(5)).until(client::isClosed);
            assertEquals(WebSocketCloseStatus.INTERNAL_SERVER_ERROR.code(), client.closeStatusCode());
        }
        waitForTracesToArrive(3);

        // server traces
        var initialRequestSpan = getSpanByName("GET /bounce", SpanKind.SERVER);
        var connectionOpenedSpan = getSpanByName("OPEN " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionOpenedSpan));
        assertEquals(initialRequestSpan.getSpanId(), connectionOpenedSpan.getLinks().get(0).getSpanContext().getSpanId());
        var connectionClosedSpan = getSpanByName("CLOSE " + bounceUri.getPath(), SpanKind.SERVER);
        assertEquals(bounceUri.getPath(), getUriAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.connectionId, getConnectionIdAttrVal(connectionClosedSpan));
        assertEquals(OtelBounceEndpoint.endpointId, getEndpointIdAttrVal(connectionClosedSpan));
        assertEquals(1, connectionClosedSpan.getLinks().size());
        assertEquals(connectionOpenedSpan.getSpanId(), connectionClosedSpan.getLinks().get(0).getSpanContext().getSpanId());
    }

    private String getConnectionIdAttrVal(SpanData connectionOpenedSpan) {
        return connectionOpenedSpan
                .getAttributes()
                .get(AttributeKey.stringKey("connection.id"));
    }

    private String getClientIdAttrVal(SpanData connectionOpenedSpan) {
        return connectionOpenedSpan
                .getAttributes()
                .get(AttributeKey.stringKey("connection.client.id"));
    }

    private String getUriAttrVal(SpanData connectionOpenedSpan) {
        return connectionOpenedSpan.getAttributes().get(URL_PATH);
    }

    private String getEndpointIdAttrVal(SpanData connectionOpenedSpan) {
        return connectionOpenedSpan
                .getAttributes()
                .get(AttributeKey.stringKey("connection.endpoint.id"));
    }

    private void waitForTracesToArrive(int expectedTracesCount) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertEquals(expectedTracesCount, spanExporter.getFinishedSpanItems().size()));
    }

    private SpanData getSpanByName(String name, SpanKind kind) {
        return spanExporter.getFinishedSpanItems()
                .stream()
                .filter(sd -> name.equals(sd.getName()))
                .filter(sd -> sd.getKind() == kind)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Expected span name '" + name + "' and kind '" + kind + "' not found: "
                                + spanExporter.getFinishedSpanItems()));
    }

    @WebSocket(path = "/bounce", endpointId = "bounce-server-endpoint-id")
    public static class OtelBounceEndpoint {

        public static final List<String> MESSAGES = new CopyOnWriteArrayList<>();
        public static CountDownLatch CLOSED_LATCH = new CountDownLatch(1);
        public static volatile String connectionId = null;
        public static volatile String endpointId = null;

        @ConfigProperty(name = "bounce-endpoint.prefix-responses", defaultValue = "false")
        boolean prefixResponses;

        @OnTextMessage
        public String onMessage(String message) {
            if (prefixResponses) {
                message = "echo 0: " + message;
            }
            MESSAGES.add(message);
            if (message.equals("throw-exception")) {
                throw new RuntimeException("Failing 'onMessage' to test behavior when an exception was thrown");
            }
            return message;
        }

        @OnOpen
        void open(WebSocketConnection connection) {
            connectionId = connection.id();
            endpointId = connection.endpointId();
        }

        @OnClose
        void onClose() {
            CLOSED_LATCH.countDown();
        }

    }

    @WebSocketClient(path = "/bounce", clientId = "bounce-client-id")
    public class OtelBounceClient {

        public static List<String> MESSAGES = new CopyOnWriteArrayList<>();
        public static CountDownLatch CLOSED_LATCH = new CountDownLatch(1);

        @OnTextMessage
        void echo(String message) {
            MESSAGES.add(message);
        }

        @OnClose
        void onClose() {
            CLOSED_LATCH.countDown();
        }

    }
}
