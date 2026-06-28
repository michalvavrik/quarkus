package io.quarkus.spiffe.client.api;

/**
 * Thrown when the client cannot communicate with the SPIRE Agent. Common causes include
 * a missing or misconfigured endpoint socket, the agent not running, or a network timeout.
 */
public final class SpiffeConnectionException extends Exception {

    public SpiffeConnectionException(String message) {
        super(message);
    }

    public SpiffeConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
