package io.quarkus.mailer.runtime.security;

import io.quarkus.mailer.runtime.Mailers;
import io.quarkus.runtime.annotations.ConfigGroup;
import io.smallrye.config.WithDefault;

@ConfigGroup
public interface MailerFormAuthenticationTokenConfig {

    /**
     * Name of the mailer used to send form authentication tokens.
     */
    @WithDefault(Mailers.DEFAULT_MAILER_NAME)
    String mailerName();

    /**
     * Subject of the email carrying the form authentication token.
     */
    @WithDefault("Your verification code")
    String subject();

    /**
     * Text of the email carrying the form authentication token.
     * The text must contain '%s', marking the position of the token.
     */
    @WithDefault("Your verification code is %s")
    String text();

    /**
     * Name of the {@link io.quarkus.security.identity.SecurityIdentity#getAttribute(String)} which contains
     * email address to which the form authentication token should be sent.
     */
    @WithDefault("mail")
    String identityAttribute();

}
