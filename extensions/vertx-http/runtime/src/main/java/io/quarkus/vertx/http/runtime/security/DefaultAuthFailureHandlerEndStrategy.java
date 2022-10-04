package io.quarkus.vertx.http.runtime.security;

public enum DefaultAuthFailureHandlerEndStrategy {
    /**
     * Special case, we don't call {@code event.end()} or {@code event.next()}.
     * Intended use is for RESTEasy Reactive as we want exception to be handled by abort chain rather than failure one.
     */
    DO_NOTHING,
    /**
     * Default behavior, unless extensions explicitly specify they are handling the auth failure themselves,
     * we send response immediately (with {@code event.end()}).
     */
    END,
    /**
     * We allow other failure handlers to handle response. If event is not handled elsewhere,
     * {@link io.quarkus.vertx.http.runtime.QuarkusErrorHandler} will end it.
     */
    NEXT_FAILURE_HANDLER;

    /**
     * The key that stores the {@link DefaultAuthFailureHandlerEndStrategy}. If no strategy is defined, {@link #END} is
     * used.
     */
    public static final String DEFAULT_AUTH_FAILURE_HANDLER_END_STRATEGY = "io.quarkus.vertx.http.default-auth-failure-handler-end-strategy";
}
