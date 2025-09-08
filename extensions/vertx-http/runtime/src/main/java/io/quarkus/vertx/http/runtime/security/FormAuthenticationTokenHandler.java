package io.quarkus.vertx.http.runtime.security;

import static io.quarkus.security.spi.runtime.SecurityEventHelper.fire;
import static io.quarkus.vertx.http.runtime.FormAuthConfig.CookieSameSite.STRICT;
import static io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent.*;
import static io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism.sendRedirect;
import static io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism.startWithSlash;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;

import jakarta.enterprise.event.Event;

import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.util.HashUtil;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.security.token.FormAuthenticationTokenSender;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

final class FormAuthenticationTokenHandler implements Handler<RoutingContext> {

    private static final Logger LOG = Logger.getLogger(FormAuthenticationTokenHandler.class);
    private static final char PRINCIPAL_TO_TOKEN_SEPARATOR = '-';
    private final Event<FormAuthenticationEvent> formAuthEvent;
    private final String onTokenGeneratedRedirectPath;
    private final FormAuthenticationTokenSender tokenSender;
    private final PersistentLoginManager loginManager;

    private FormAuthenticationTokenHandler(Event<FormAuthenticationEvent> formAuthEvent, PersistentLoginManager loginManager,
            String onTokenGeneratedRedirectPath, FormAuthenticationTokenSender tokenSender) {
        this.formAuthEvent = formAuthEvent;
        this.onTokenGeneratedRedirectPath = onTokenGeneratedRedirectPath;
        this.tokenSender = tokenSender;
        this.loginManager = loginManager;
    }

    void handleTokenRequest(SecurityIdentity identity, RoutingContext routingContext, String userPrincipal) {
        sendAuthenticationToken(identity, routingContext, userPrincipal);
        if (onTokenGeneratedRedirectPath != null) {
            sendRedirect(routingContext, onTokenGeneratedRedirectPath);
        } else {
            routingContext.response().setStatusCode(204).end();
        }
    }

    String findUserPrincipalByToken(RoutingContext routingContext, String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        TokenAndPrincipal storedRequest = getStoredUserPrincipalAndToken(routingContext);
        if (storedRequest == null) {
            LOG.debugf("Sent token not found in request cookie, cannot compare it with token '%s'", token);
            return null;
        }
        String tokenHash = HashUtil.sha512(token);
        if (tokenHash.equals(storedRequest.token)) {
            LOG.debug("Provided token matches sent token");
            return storedRequest.principal;
        }
        LOG.debugf("Provided token '%s' does not match sent token", token);
        return null;
    }

    private void sendAuthenticationToken(SecurityIdentity identity, RoutingContext event, String username) {
        if (identity != null && !identity.isAnonymous()) {
            LOG.debugf("Received the authentication token request for user '%s'", username);
            sendAndStoreAuthenticationToken(identity, event, username);
        } else {
            // identity provider should just fail, incorrect credentials must lead to auth failure
            var failure = new AuthenticationFailedException("Failed to authenticate user " + username);
            if (formAuthEvent != null) {
                fire(formAuthEvent, createAuthenticationTokenEvent(failure, username, event));
            }
            LOG.warn("Authentication failed for username '" + username + "'", failure);
        }
    }

    private void sendAndStoreAuthenticationToken(SecurityIdentity identity, RoutingContext event, String username) {
        // this must be async, because we don't want response time to indicate if the username is recognized
        Uni.createFrom().voidItem()
                .replaceWith(() -> generateAuthenticationToken(identity))
                .flatMap(tokenCredential -> tokenSender.send(identity, tokenCredential).replaceWith(tokenCredential))
                .invoke(tokenCredential -> store(identity, tokenCredential, event))
                .invoke(tokenCredential -> Arrays.fill(tokenCredential.getPassword(), 'Q'))
                .subscribe().with(new Consumer<Object>() {
                    @Override
                    public void accept(Object ignored) {
                        if (formAuthEvent != null) {
                            fire(formAuthEvent, createAuthenticationTokenEvent(identity, username, event));
                        }
                        LOG.debug("Sent and stored the authentication token for username '" + username + "'");
                    }
                }, new Consumer<Throwable>() {
                    @Override
                    public void accept(Throwable failure) {
                        if (formAuthEvent != null) {
                            fire(formAuthEvent, createAuthenticationTokenEvent(failure, username, event));
                        }
                        LOG.warn("Request to send the authentication token authentication failed for username '"
                                + username + "'", failure);
                    }
                });
    }

    private void store(SecurityIdentity securityIdentity, PasswordCredential tokenCredential, RoutingContext event) {
        String principalName = securityIdentity.getPrincipal().getName();
        if (principalName.isBlank()) {
            throw new IllegalArgumentException("Principal name cannot be blank");
        }
        String tokenHash = HashUtil.sha512(new String(tokenCredential.getPassword()).getBytes(UTF_8));
        // what do we store? we store token hash, we store principal name, and ... UUID I guess ?
        String cookieValue = principalName + PRINCIPAL_TO_TOKEN_SEPARATOR + tokenHash;
        loginManager.save(cookieValue, event);
    }

    static FormAuthenticationTokenHandler of(FormAuthConfig formConfig, String key,
            Event<FormAuthenticationEvent> formAuthEvent) {
        var tokenConfig = formConfig.authenticationToken();
        var tokenSender = Arc.container().select(FormAuthenticationTokenSender.class).get();
        var loginManager = new PersistentLoginManager(key, tokenConfig.cookieName(), tokenConfig.expiresIn().toMillis(),
                -1, true, STRICT.name(), formConfig.cookiePath().orElse(null),
                tokenConfig.expiresIn().getSeconds(), formConfig.cookieDomain().orElse(null));
        return new FormAuthenticationTokenHandler(formAuthEvent, loginManager,
                startWithSlash(tokenConfig.redirectPath().orElse(null)), tokenSender);
    }

    private TokenAndPrincipal getStoredUserPrincipalAndToken(RoutingContext event) {
        var cookieValue = loginManager.getAndRemoveCookie(event);
        if (cookieValue != null && cookieValue.indexOf(PRINCIPAL_TO_TOKEN_SEPARATOR) > 1) {
            return new TokenAndPrincipal(cookieValue);
        }
        return null;
    }

    private static PasswordCredential generateAuthenticationToken(SecurityIdentity identity) {
        // one is added to make sure that the authentication token is unique per user (only one token is allowed per user)
        return new PasswordCredential((HashUtil.sha512(identity.getPrincipal().getName()) + UUID.randomUUID()).toCharArray());
    }

    @Override
    public void handle(RoutingContext routingContext) {
        // either query or form gives us email address
        // if we agree that it exists, and we enabled sending token for that address
        // then we get identity for the principal
        // send and store token
        // TODO: get email address programmatically? assembling things?
        // TODO: document rate limiting for this endpoint
        routingContext.request().setExpectMultipart(true);
        routingContext.request().endHandler(new Handler<Void>() {
            @Override
            public void handle(Void event) {
                try {
                    String userPrincipal = routingContext.request().getFormAttribute("TODO");
                    // TODO: validation and then get security identity
                } finally {
                    // TODO: end? if not ended!
                }
            }
        });
        routingContext.request().resume();
    }

    private record TokenAndPrincipal(String token, String principal) {

        private TokenAndPrincipal(String cookieValue) {
            this(getToken(cookieValue), getPrincipal(cookieValue));
        }

        private static String getPrincipal(String cookieValue) {
            return cookieValue.substring(0, cookieValue.indexOf(PRINCIPAL_TO_TOKEN_SEPARATOR));
        }

        private static String getToken(String cookieValue) {
            return cookieValue.substring(cookieValue.indexOf(PRINCIPAL_TO_TOKEN_SEPARATOR) + 1);
        }

    }
}
