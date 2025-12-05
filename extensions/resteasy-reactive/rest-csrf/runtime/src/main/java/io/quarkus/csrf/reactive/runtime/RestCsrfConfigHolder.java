package io.quarkus.csrf.reactive.runtime;

import static io.quarkus.vertx.http.runtime.security.HttpSecurityConfiguration.getProgrammaticCsrfConfig;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.logging.Logger;

import io.quarkus.runtime.LaunchMode;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;

@ApplicationScoped
public class RestCsrfConfigHolder {

    // used in DEV mode to detect changes in the generated token size
    private static volatile Integer previousTokenSize = null;

    private final RestCsrfConfig config;

    RestCsrfConfigHolder(RestCsrfConfig config, VertxHttpConfig httpConfig, VertxHttpBuildTimeConfig httpBuildTimeConfig) {
        if (getProgrammaticCsrfConfig(httpConfig, httpBuildTimeConfig) instanceof RestCsrfConfig programmaticConfig) {
            this.config = programmaticConfig;
        } else {
            this.config = config;
        }
        if (LaunchMode.current() == LaunchMode.DEVELOPMENT) {
            if (previousTokenSize != null && previousTokenSize != this.config.tokenSize()) {
                Logger.getLogger(RestCsrfConfigHolder.class).infof("Generated token size has changed from %d to %d." +
                        " Thus, previously generated CSRF token is not valid anymore. Consider deleting the '%s' cookie in your browser.",
                        previousTokenSize, this.config.tokenSize(), this.config.cookieName());
            }
            previousTokenSize = this.config.tokenSize();
        }
    }

    RestCsrfConfig getConfig() {
        return config;
    }
}
