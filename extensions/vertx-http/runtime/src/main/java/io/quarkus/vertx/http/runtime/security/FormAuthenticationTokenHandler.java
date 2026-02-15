package io.quarkus.vertx.http.runtime.security;

import static io.quarkus.security.spi.runtime.SecurityEventHelper.fire;
import static io.quarkus.vertx.http.runtime.security.CookieFormAuthenticationTokenStorage.addPersistentLoginManager;
import static io.quarkus.vertx.http.runtime.security.CookieFormAuthenticationTokenStorage.removePersistentLoginManager;
import static io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent.createAuthenticationTokenEvent;

import java.security.SecureRandom;
import java.util.Arrays;

import jakarta.enterprise.event.Event;

import org.jboss.logging.Logger;

import io.quarkus.arc.ClientProxy;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.spi.runtime.FormAuthenticationTokenSender;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.security.form.token.FormAuthenticationTokenStorage;
import io.smallrye.common.vertx.VertxContext;
import io.smallrye.mutiny.Uni;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

final class FormAuthenticationTokenHandler {

    private static final Logger LOG = Logger.getLogger(FormAuthenticationTokenHandler.class);
    /**
     * Does not contain 0, O, 1, I, l to avoid confusion between number and lookalike letters.
     * Vowels (except Y) are removed as well to limit chance we get undesirable words (like rude words).
     */
    private static final String SAFE_TOKEN_CHARS = "23456789BCDFGHJKMNPQRSTVWXYZ";
    private final FormAuthenticationTokenSender tokenSender;
    private final String postTokenGenerationLocation;
    private final String tokenFormParameter;
    private final Event<FormAuthenticationEvent> formAuthEvent;
    private final SecureRandom secureRandom;
    private final String usernameParameter;
    private final int tokenLength;
    private final FormAuthenticationTokenStorage tokenStorage;
    /**
     * We add this login manager to the active {@link RoutingContext} in case that the token storage or its delegate
     * needs it.
     */
    private final PersistentLoginManager loginManager;
    private final FormAuthConfig.FormAuthenticationToken tokenConfig;

    private FormAuthenticationTokenHandler(FormAuthenticationTokenSender tokenSender,
            Event<FormAuthenticationEvent> formAuthEvent, String usernameParameter,
            FormAuthenticationTokenStorage tokenStorage, PersistentLoginManager loginManager,
            FormAuthConfig.FormAuthenticationToken tokenConfig) {
        this.tokenSender = tokenSender;
        this.postTokenGenerationLocation = tokenConfig.tokenPage().orElse(null);
        this.tokenFormParameter = tokenConfig.tokenParameter();
        this.formAuthEvent = formAuthEvent;
        this.usernameParameter = usernameParameter;
        this.tokenLength = tokenConfig.tokenLength();
        this.tokenStorage = tokenStorage;
        this.loginManager = loginManager;
        this.tokenConfig = tokenConfig;
        this.secureRandom = new SecureRandom();
    }

    Uni<SecurityIdentity> authenticateUsingToken(String token, IdentityProviderManager identityProviderManager,
            RoutingContext routingContext) {
        addPersistentLoginManager(routingContext, loginManager);
        return tokenStorage.findPrincipalNameByToken(token, routingContext)
                .flatMap(principalName -> {
                    removePersistentLoginManager(routingContext);
                    if (principalName == null || principalName.isEmpty()) {
                        return Uni.createFrom().failure(new AuthenticationFailedException(
                                "Cannot authentication with unknown or invalid token: " + token));
                    }
                    LOG.debugf("Found principal name '%s' for form authentication token '%s'", principalName, token);
                    return findSecurityIdentityByPrincipalName(identityProviderManager, routingContext, principalName);
                });
    }

    String getTokenFormParameter() {
        return tokenFormParameter;
    }

    String getPostTokenGenerationLocation() {
        return postTokenGenerationLocation;
    }

    FormAuthConfig.FormAuthenticationToken getTokenConfig() {
        return tokenConfig;
    }

    boolean isTokenGenerationPath(RoutingContext context) {
        return context.normalizedPath().endsWith(postTokenGenerationLocation)
                && context.request().method().equals(HttpMethod.POST);
    }

    Uni<Void> generateAndSendToken(RoutingContext context, IdentityProviderManager identityProviderManager) {
        context.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(uniEmitter -> {
            context.request().endHandler(ignored -> {
                try {
                    MultiMap res = context.request().formAttributes();
                    String jUsername = res.get(usernameParameter);
                    if (jUsername == null || jUsername.isEmpty()) {
                        LOG.debugf("Could not send token as username was not present in the posted result for %s", context);
                        uniEmitter.complete(null);
                    } else {
                        char[] token = generateToken();
                        addPersistentLoginManager(context, loginManager);
                        tokenStorage.storeToken(token, jUsername, context).subscribe().with(
                                ignored2 -> {
                                    removePersistentLoginManager(context);
                                    LOG.debugf("Stored token for the token request with username '%s'", jUsername);
                                    sendToken(token, jUsername, identityProviderManager, context);
                                    uniEmitter.complete(null);
                                },
                                failure -> {
                                    removePersistentLoginManager(context);
                                    LOG.debug("Failed to store token", failure);
                                    fire(formAuthEvent, createAuthenticationTokenEvent(failure, jUsername));
                                    uniEmitter.fail(failure);
                                });
                    }
                } catch (Throwable t) {
                    uniEmitter.fail(t);
                }
            });
            context.request().resume();
        });
    }

    private void sendToken(char[] token, String principalName, IdentityProviderManager identityProviderManager,
            RoutingContext context) {
        // this must be asynchronous, so that we don't signal by the response time if the principal name exists
        // the incoming HTTP request is closed right after calling this method, therefore we run this on a nested context
        var nestedContext = VertxContext.newNestedContext(context.vertx().getOrCreateContext());
        findSecurityIdentityByPrincipalName(identityProviderManager, context, principalName)
                .flatMap(securityIdentity -> {
                    if (securityIdentity == null || securityIdentity.isAnonymous()) {
                        return Uni.createFrom().failure(new AuthenticationFailedException(
                                "Cannot find SecurityIdentity for principal name " + principalName));
                    }
                    return tokenSender.sendToken(token, securityIdentity).replaceWith(securityIdentity);
                })
                .runSubscriptionOn(command -> nestedContext.runOnContext(unused -> command.run()))
                .subscribe().with(identity -> {
                    LOG.debugf("Sent token to SecurityIdentity with principal name '%s'", identity.getPrincipal().getName());
                    fire(formAuthEvent, createAuthenticationTokenEvent(identity, token))
                            .whenComplete((e, f) -> Arrays.fill(token, '0'));
                },
                        failure -> {
                            LOG.debug("Failed to send token", failure);
                            fire(formAuthEvent, createAuthenticationTokenEvent(failure, principalName));
                        });
    }

    private char[] generateToken() {
        // this may seem like a lot, but since in the default implementation we don't have OTP brute-force protection,
        // and we are reusing the session enc key to encrypt cookie with the token request, and there is a chance that
        // some users won't rotate enc key, we need high entropy in order to limit possibility that someone will succeed
        // in brute-force attacks
        char[] token = new char[tokenLength];
        for (int i = 0; i < tokenLength; i++) {
            int randomIndex = secureRandom.nextInt(SAFE_TOKEN_CHARS.length());
            token[i] = SAFE_TOKEN_CHARS.charAt(randomIndex);
        }
        return token;
    }

    static FormAuthenticationTokenHandler of(FormAuthConfig runtimeForm, FormAuthenticationTokenSender tokenSender,
            Event<FormAuthenticationEvent> formAuthEvent, PersistentLoginManager loginManager,
            FormAuthenticationTokenStorage tokenStorage) {
        if (tokenSender == null) {
            if (tokenStorage != null) {
                throw new IllegalArgumentException("Cannot enable form authentication token feature. Found "
                        + ClientProxy.unwrap(tokenStorage).getClass().getName()
                        + ", but no " + FormAuthenticationTokenSender.class.getName());
            }
            return null;
        } else {
            var tokenConfig = runtimeForm.token();
            var aTokenStorage = tokenStorage == null
                    ? new CookieFormAuthenticationTokenStorage(tokenConfig)
                    : tokenStorage;
            return new FormAuthenticationTokenHandler(tokenSender, formAuthEvent, runtimeForm.usernameParameter(),
                    aTokenStorage, loginManager, tokenConfig);
        }
    }

    private static Uni<SecurityIdentity> findSecurityIdentityByPrincipalName(IdentityProviderManager identityProviderManager,
            RoutingContext routingContext, String principal) {
        return identityProviderManager.authenticate(HttpSecurityUtils
                .setRoutingContextAttribute(new TrustedAuthenticationRequest(principal), routingContext));
    }

}
