package io.quarkus.websockets.next.runtime.telemetry;

import java.util.function.Function;

import io.quarkus.websockets.next.runtime.WebSocketConnectionBase;
import io.quarkus.websockets.next.runtime.WebSocketEndpoint;

public final class WebsocketTelemetryProvider {

    private final Function<String, SendingInterceptor> pathToClientSendingInterceptor;
    private final Function<String, SendingInterceptor> pathToServerSendingInterceptor;
    private final Function<String, ErrorInterceptor> pathToClientErrorInterceptor;
    private final Function<String, ErrorInterceptor> pathToServerErrorInterceptor;
    private final Function<TelemetryWebSocketEndpointContext, WebSocketEndpoint> serverEndpointDecorator;
    private final Function<TelemetryWebSocketEndpointContext, WebSocketEndpoint> clientEndpointDecorator;
    private final Function<String, ConnectionInterceptor> pathToClientConnectionInterceptor;
    private final Function<String, ConnectionInterceptor> pathToServerConnectionInterceptor;
    private final boolean clientTelemetryEnabled;
    private final boolean serverTelemetryEnabled;

    WebsocketTelemetryProvider(Function<String, SendingInterceptor> pathToClientSendingInterceptor,
            Function<String, SendingInterceptor> pathToServerSendingInterceptor,
            Function<String, ErrorInterceptor> pathToClientErrInterceptor,
            Function<String, ErrorInterceptor> pathToServerErrInterceptor,
            Function<TelemetryWebSocketEndpointContext, WebSocketEndpoint> serverEndpointDecorator,
            Function<TelemetryWebSocketEndpointContext, WebSocketEndpoint> clientEndpointDecorator,
            Function<String, ConnectionInterceptor> pathToClientConnectionInterceptor,
            Function<String, ConnectionInterceptor> pathToServerConnectionInterceptor) {
        this.serverTelemetryEnabled = pathToServerSendingInterceptor != null || pathToServerErrInterceptor != null
                || serverEndpointDecorator != null || pathToServerConnectionInterceptor != null;
        this.pathToServerSendingInterceptor = pathToServerSendingInterceptor;
        this.pathToServerErrorInterceptor = pathToServerErrInterceptor;
        this.serverEndpointDecorator = serverEndpointDecorator;
        this.pathToServerConnectionInterceptor = pathToServerConnectionInterceptor;
        this.clientTelemetryEnabled = clientEndpointDecorator != null || pathToClientSendingInterceptor != null
                || pathToClientErrInterceptor != null || pathToClientConnectionInterceptor != null;
        this.clientEndpointDecorator = clientEndpointDecorator;
        this.pathToClientSendingInterceptor = pathToClientSendingInterceptor;
        this.pathToClientErrorInterceptor = pathToClientErrInterceptor;
        this.pathToClientConnectionInterceptor = pathToClientConnectionInterceptor;
    }

    /**
     * This method may only be called on the Vert.x context of the initial HTTP request as it collects context data.
     *
     * @param path endpoint path with path param placeholders
     * @return TelemetryDecorator
     */
    public TelemetrySupport createServerTelemetrySupport(String path) {
        if (serverTelemetryEnabled) {
            return new TelemetrySupport(getServerSendingInterceptor(path), getServerErrorInterceptor(path),
                    getServerConnectionInterceptor(path)) {
                @Override
                public WebSocketEndpoint decorate(WebSocketEndpoint endpoint, WebSocketConnectionBase connection) {
                    if (serverEndpointDecorator == null) {
                        return endpoint;
                    }
                    return serverEndpointDecorator
                            .apply(new TelemetryWebSocketEndpointContext(endpoint, connection, path, getContextData()));
                }
            };
        }
        return null;
    }

    public TelemetrySupport createClientTelemetrySupport(String path) {
        if (clientTelemetryEnabled) {
            return new TelemetrySupport(getClientSendingInterceptor(path), getClientErrorInterceptor(path),
                    getClientConnectionInterceptor(path)) {
                @Override
                public WebSocketEndpoint decorate(WebSocketEndpoint endpoint, WebSocketConnectionBase connection) {
                    if (clientEndpointDecorator == null) {
                        return endpoint;
                    }
                    return clientEndpointDecorator
                            .apply(new TelemetryWebSocketEndpointContext(endpoint, connection, path, getContextData()));
                }
            };
        }
        return null;
    }

    private ErrorInterceptor getServerErrorInterceptor(String path) {
        return pathToServerErrorInterceptor == null ? null : pathToServerErrorInterceptor.apply(path);
    }

    private SendingInterceptor getServerSendingInterceptor(String path) {
        return pathToServerSendingInterceptor == null ? null : pathToServerSendingInterceptor.apply(path);
    }

    private ConnectionInterceptor getServerConnectionInterceptor(String path) {
        return pathToServerConnectionInterceptor == null ? null : pathToServerConnectionInterceptor.apply(path);
    }

    private ErrorInterceptor getClientErrorInterceptor(String path) {
        return pathToClientErrorInterceptor == null ? null : pathToClientErrorInterceptor.apply(path);
    }

    private SendingInterceptor getClientSendingInterceptor(String path) {
        return pathToClientSendingInterceptor == null ? null : pathToClientSendingInterceptor.apply(path);
    }

    private ConnectionInterceptor getClientConnectionInterceptor(String path) {
        return pathToClientConnectionInterceptor == null ? null : pathToClientConnectionInterceptor.apply(path);
    }

}
