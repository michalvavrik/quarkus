package io.quarkus.it.openapi.security;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class TestHeaderStorage {

    private volatile String headerValue = null;

    public String getHeaderValue() {
        return headerValue;
    }

    public void setHeaderValue(String headerValue) {
        this.headerValue = headerValue;
    }
}
