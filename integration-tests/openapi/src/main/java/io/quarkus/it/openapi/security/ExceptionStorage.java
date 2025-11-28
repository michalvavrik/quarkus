package io.quarkus.it.openapi.security;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.logging.Log;

@ApplicationScoped
public class ExceptionStorage {

    private volatile Exception exception = null;

    public Exception getException() {
        return exception;
    }

    public void setException(Exception exception) {
        Log.info("Setting exception value to " + exception);
        this.exception = exception;
    }
}
