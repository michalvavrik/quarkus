package io.quarkus.vertx.http.runtime.security.config;

import java.util.HashMap;
import java.util.Map;

public final class HttpSecurityConfigBuilder {

    private static final String PREFIX = "quarkus.http.auth.";
    private static final String PROACTIVE_AUTH = PREFIX + "proactive";
    private static final String REALM = PREFIX + "realm";
    private static final String BASIC_AUTH = PREFIX + "basic";
    private final Map<String, String> properties;

    HttpSecurityConfigBuilder() {
        properties = new HashMap<>();
    }

    public HttpSecurityConfigBuilder proactive() {
        return proactive(true);
    }

    public HttpSecurityConfigBuilder proactive(boolean proactive) {
        properties.put(PROACTIVE_AUTH, Boolean.toString(proactive));
        return this;
    }

    public HttpSecurityConfigBuilder basic() {
        return basic(true);
    }

    public HttpSecurityConfigBuilder basic(boolean basic) {
        properties.put(BASIC_AUTH, Boolean.toString(basic));
        return this;
    }

    public HttpSecurityConfigBuilder realm(String realm) {
        properties.put(REALM, realm);
        return this;
    }

    Map<String, String> build() {
        return Map.copyOf(properties);
    }

}
