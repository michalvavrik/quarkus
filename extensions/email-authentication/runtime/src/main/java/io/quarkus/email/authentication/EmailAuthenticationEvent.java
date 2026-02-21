package io.quarkus.email.authentication;

import io.quarkus.security.spi.runtime.SecurityEvent;

/**
 * A security event used to report email authentication events such as a sending of the email authentication token.
 */
public interface EmailAuthenticationEvent extends SecurityEvent {

    /**
     * A {@link SecurityEvent#getEventProperties()} key of a principal name sent in an authentication token request.
     * This event attribute is added together with the {@link #FAILURE_KEY} attribute.
     */
    String PRINCIPAL_NAME_KEY = "io.quarkus.email.authentication.EmailAuthenticationEvent#PRINCIPAL_NAME";

    /**
     * A {@link SecurityEvent#getEventProperties()} key of a {@link Throwable} when the authentication token request fails.
     */
    String FAILURE_KEY = "io.quarkus.email.authentication.EmailAuthenticationEvent#FAILURE";

    /**
     * A {@link SecurityEvent#getEventProperties()} key of the email authentication token.
     */
    String AUTHENTICATION_TOKEN_KEY = "io.quarkus.email.authentication.EmailAuthenticationEvent#AUTHENTICATION_TOKEN";

    enum EmailAuthenticationEventType {
        /**
         * Event fired when a user was successfully authenticated with a call to the Email mechanism POST location.
         */
        EMAIL_LOGIN,
        /**
         * Event fired when authentication token was requested, the request was processed and sent.
         * If Quarkus failed to send the token, this event is fired with the failure stored in the event properties.
         */
        AUTHENTICATION_TOKEN
    }

    /**
     * Email authentication event type.
     *
     * @return {@link EmailAuthenticationEventType}
     */
    EmailAuthenticationEventType getEventType();

}
