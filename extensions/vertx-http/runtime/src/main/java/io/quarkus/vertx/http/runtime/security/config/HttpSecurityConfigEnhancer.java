package io.quarkus.vertx.http.runtime.security.config;

import org.eclipse.microprofile.config.spi.ConfigSource;

import java.util.Map;
import java.util.Set;

public abstract class HttpSecurityConfigEnhancer implements ConfigSource {

    private final Map<String, String> properties;

    protected HttpSecurityConfigEnhancer() {
        var builder = new HttpSecurityConfigBuilder();
        enhance(builder);
        properties = builder.build();
    }

    protected abstract void enhance(HttpSecurityConfigBuilder builder);

    @Override
    public final Map<String, String> getProperties() {
        return properties;
    }

    @Override
    public final int getOrdinal() {
        // Higher priority then application.properties, but still can be overridden
        // by environment vars and system properties.
        return 270;
    }

    @Override
    public final Set<String> getPropertyNames() {
        return properties.keySet();
    }

    @Override
    public final String getValue(String propertyName) {
        return properties.get(propertyName);
    }

    @Override
    public final String getName() {
        return HttpSecurityConfigEnhancer.class.getName();
    }
}
