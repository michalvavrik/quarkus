package io.quarkus.mailer.runtime;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
@ConfigMapping(prefix = "quarkus.mailer")
public interface MailersBuildTimeConfig {

    /**
     * Caches data from attachment's Stream to a temporary file.
     * It tries to delete it after sending email.
     */
    @WithDefault("false")
    boolean cacheAttachments();

    /**
     * If the default form authentication token sender implementation is enabled.
     * This sender is used by the form-based authentication mechanism.
     * Please note that Quarkus Security and Vert.x HTTP extensions must be present if this feature is enabled.
     */
    @WithName("form-token-sender.enabled")
    @WithDefault("false")
    boolean formTokenSenderEnabled();
}
