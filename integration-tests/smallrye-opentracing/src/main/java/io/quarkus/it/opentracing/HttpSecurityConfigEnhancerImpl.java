package io.quarkus.it.opentracing;

import io.quarkus.vertx.http.runtime.security.config.HttpSecurityConfigBuilder;
import io.quarkus.vertx.http.runtime.security.config.HttpSecurityConfigEnhancer;

public class HttpSecurityConfigEnhancerImpl extends HttpSecurityConfigEnhancer {

    @Override
    protected void enhance(HttpSecurityConfigBuilder builder) {
        builder.proactive(true);
    }
}
