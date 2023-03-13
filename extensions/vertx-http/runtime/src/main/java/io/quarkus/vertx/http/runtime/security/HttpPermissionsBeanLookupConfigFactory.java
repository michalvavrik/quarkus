package io.quarkus.vertx.http.runtime.security;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.quarkus.runtime.configuration.ConfigBuilder;
import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;

/**
 * Runtime config source factory that adds single configuration property {@link #USER_DEFINED_HTTP_PERMISSIONS}
 * if {@link io.quarkus.vertx.http.runtime.AuthConfig#permissions} are not empty.
 * It is only possible to programmatically look up {@link PathMatchingHttpSecurityPolicy} bean
 * if {@link #USER_DEFINED_HTTP_PERMISSIONS} is true.
 */
public class HttpPermissionsBeanLookupConfigFactory implements ConfigSourceFactory {

    static final String USER_DEFINED_HTTP_PERMISSIONS = "quarkus.http.auth.permissions-present";

    private HttpPermissionsBeanLookupConfigFactory() {
    }

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext configSourceContext) {
        var namesIterator = configSourceContext.iterateNames();
        while (namesIterator.hasNext()) {
            // check if user defined any HTTP permissions
            if (namesIterator.next().startsWith("quarkus.http.auth.permission.")) {
                // allow 'PathMatchingHttpSecurityPolicy' bean to be looked up programmatically
                return Set.of(createConfigSource());
            }
        }

        // no HTTP permissions will be checked
        return Set.of();
    }

    private static MapBackedConfigSource createConfigSource() {
        return new MapBackedConfigSource(HttpAuthenticationMechanism.class.getName(),
                Map.of(USER_DEFINED_HTTP_PERMISSIONS, "true")) {
        };
    }

    public static class HttpPermissionsBeanLookupConfigBuilder implements ConfigBuilder {

        @Override
        public SmallRyeConfigBuilder configBuilder(SmallRyeConfigBuilder builder) {
            return builder.withSources(new HttpPermissionsBeanLookupConfigFactory());
        }
    }

}
