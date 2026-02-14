package io.quarkus.vertx.http.runtime.security;

import java.time.Instant;
import java.util.UUID;
import java.util.random.RandomGenerator;

import jakarta.enterprise.event.Event;

import org.jboss.logging.Logger;

import io.quarkus.runtime.util.HashUtil;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.spi.runtime.FormAuthenticationTokenSender;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.smallrye.mutiny.Uni;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

final class FormAuthenticationTokenHandler {

    private static final Logger LOG = Logger.getLogger(FormAuthenticationTokenHandler.class);
    private final FormAuthenticationTokenSender tokenSender;
    private final String postTokenGenerationLocation;
    private final String tokenFormParameter;
    private final Event<FormAuthenticationEvent> formAuthEvent;
    private final PersistentLoginManager loginManager;
    private final RandomGenerator randomGenerator;
    private final String cookieName;
    private final String usernameParameter;

    private FormAuthenticationTokenHandler(FormAuthenticationTokenSender tokenSender, String postTokenGenerationLocation,
            String tokenFormParameter, Event<FormAuthenticationEvent> formAuthEvent, PersistentLoginManager loginManager,
            String cookieName, String usernameParameter) {
        this.tokenSender = tokenSender;
        this.postTokenGenerationLocation = postTokenGenerationLocation;
        this.tokenFormParameter = tokenFormParameter;
        this.formAuthEvent = formAuthEvent;
        this.loginManager = loginManager;
        this.cookieName = cookieName;
        this.usernameParameter = usernameParameter;
        this.randomGenerator = RandomGenerator.getDefault();
    }

    Uni<SecurityIdentity> authenticateUsingToken(String token, IdentityProviderManager identityProviderManager,
            RoutingContext routingContext) {
        // FIXME: decrypt token!! salt!
        // FIXME: decode token -> if not possible then completion exception
        // FIXME: decoded token -> validate timestamp, and use username to authenticate
        // FIXME: remove cookie!!!!!!

        String principal = null; // FIXME: impl. me1
        return identityProviderManager.authenticate(HttpSecurityUtils
                .setRoutingContextAttribute(new TrustedAuthenticationRequest(principal), routingContext));
    }

    String getTokenFormParameter() {
        return tokenFormParameter;
    }

    String getPostTokenGenerationLocation() {
        return postTokenGenerationLocation;
    }

    boolean isTokenGenerationPath(RoutingContext context) {
        return context.normalizedPath().endsWith(postTokenGenerationLocation)
                && context.request().method().equals(HttpMethod.POST);
    }

    Uni<Void> generateAndSendToken(RoutingContext context) {
        context.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(uniEmitter -> {
            context.request().endHandler(event -> {
                try {
                    MultiMap res = context.request().formAttributes();
                    String jUsername = res.get(usernameParameter);
                    if (jUsername == null || jUsername.isEmpty()) {
                        LOG.debugf("Could not send token as username was not present in the posted result for %s", context);
                        uniEmitter.complete(null);
                        return;
                    }

                    char[] token = generateToken(jUsername);
                    // TODO: store as cookie
                    sendToken(token, jUsername);
                    uniEmitter.complete(null);
                } catch (Throwable t) {
                    uniEmitter.fail(t);
                }
            });
            context.request().resume();
        });

        // FIXME: generate token and save it to the session cookie
        // FIXME: send the token asynchronously
        // fixme: send the event if it is not null after the token was sent! and log failure otherwise
        //            String emailAddress = securityIdentity.getAttribute(EMAIL_ATTRIBUTE_KEY);
        //            if (emailAddress == null || emailAddress.isBlank()) {
        //                return Uni.createFrom().failure(new IllegalArgumentException(
        //                        "SecurityIdentity must have attribute '%s' with email address".formatted(EMAIL_ATTRIBUTE_KEY)));
        //            }
    }

    // FIXME: impl. me! and remove the comments
    // so how does it work????
    // 1. if session cookie -> treat as any other form-based auth mech, that is:
    //      -> auth
    //      -> allow to send a new request for token if a different principal
    //      -> allow to accept another token if a different from current principal
    // 2. if post page -> require token or fail
    // 3. if token generation path -> require principal or fail!
    // 4. if no session cookie, redirect to login page or 401
    // 5. on auth failure etc. redirect to error page

    private void sendToken(char[] token, String principalName) {
        // this must be asynchronous, so that we don't signal by the response time if the principal name exists
        // TODO: get email by retrieving the security identity first!
        // FIXME: impl. me!
        // FIXME: maybe, the token should be used as enc key for the cookie, so that we can only decrypt it using it?
        //      or maybe, some combination with enc key? yeah, it cannot be just the token because then users will
        //      be able to temper with it!!!
    }

    private char[] generateToken(String principalName) {
        // this may seem like a lot, but since we don't have OTP brute-force protection, and we are reusing the session
        // enc key to encrypt cookie with the token request, and there is a chance that some users won't rotate enc key
        // we need to limit possibility that someone will generate many keys in order to infer our enc key
        return (HashUtil.sha512(Instant.now() + principalName + randomGenerator.nextLong()) + UUID.randomUUID()).toCharArray();
    }

    static FormAuthenticationTokenHandler of(FormAuthConfig runtimeForm, FormAuthenticationTokenSender tokenSender,
            Event<FormAuthenticationEvent> formAuthEvent, PersistentLoginManager loginManager) {
        if (tokenSender == null) {
            return null;
        } else {
            var tokenConfig = runtimeForm.token();
            return new FormAuthenticationTokenHandler(tokenSender, tokenConfig.tokenPage().orElse(null),
                    tokenConfig.tokenParameter(), formAuthEvent, loginManager, tokenConfig.cookieName(),
                    runtimeForm.usernameParameter());
        }
    }
}
