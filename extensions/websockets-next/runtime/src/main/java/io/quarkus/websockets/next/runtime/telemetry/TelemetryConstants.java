package io.quarkus.websockets.next.runtime.telemetry;

public interface TelemetryConstants {

    /**
     * OpenTelemetry attributes added to spans created for opened and closed connections.
     */
    String CONNECTION_ID_ATTR_KEY = "connection.id";
    String CONNECTION_ENDPOINT_ATTR_KEY = "connection.endpoint.id";
    String CONNECTION_CLIENT_ATTR_KEY = "connection.client.id";

    /**
     * Number of messages received by server endpoints.
     */
    String SERVER_MESSAGES_COUNT_RECEIVED = "quarkus.websockets.server.messages.count.received";

    /**
     * Counts all the WebSockets server endpoint errors.
     */
    String SERVER_MESSAGES_COUNT_ERRORS = "quarkus.websockets.server.messages.count.errors";

    /**
     * Number of bytes sent from server endpoints.
     */
    String SERVER_MESSAGES_COUNT_SENT_BYTES = "quarkus.websockets.server.messages.count.sent.bytes";

    /**
     * Number of bytes received by server endpoints.
     */
    String SERVER_MESSAGES_COUNT_RECEIVED_BYTES = "quarkus.websockets.server.messages.count.received.bytes";

    /**
     * Number of messages sent from client endpoints.
     */
    String CLIENT_MESSAGES_COUNT_SENT = "quarkus.websockets.client.messages.count.sent";

    /**
     * Counts all the WebSockets client endpoint errors.
     */
    String CLIENT_MESSAGES_COUNT_ERRORS = "quarkus.websockets.client.messages.count.errors";

    /**
     * Number of bytes sent from client endpoints.
     */
    String CLIENT_MESSAGES_COUNT_SENT_BYTES = "quarkus.websockets.client.messages.count.sent.bytes";

    /**
     * Number of bytes received by client endpoints.
     */
    String CLIENT_MESSAGES_COUNT_RECEIVED_BYTES = "quarkus.websockets.client.messages.count.received.bytes";

    /**
     * Metric key for opened server WebSocket connections.
     */
    String CLIENT_CONNECTION_OPENED = "quarkus.websockets.client.connection.opened";

    /**
     * Metric key for opened server WebSocket connections.
     */
    String SERVER_CONNECTION_OPENED = "quarkus.websockets.server.connection.opened";

    /**
     * Metric key used when opening of a client WebSocket connection failed.
     */
    String CLIENT_CONNECTION_OPENED_ERROR = "quarkus.websockets.client.connection.opened.error";

    /**
     * Metric key used when opening of a server WebSocket connection failed.
     */
    String SERVER_CONNECTION_OPENED_ERROR = "quarkus.websockets.server.connection.opened.error";

    /**
     * Metric key for closed client WebSocket connections.
     */
    String CLIENT_CONNECTION_CLOSED = "quarkus.websockets.client.connection.closed";

    /**
     * Metric key for closed server WebSocket connections.
     */
    String SERVER_CONNECTION_CLOSED = "quarkus.websockets.server.connection.closed";
}
