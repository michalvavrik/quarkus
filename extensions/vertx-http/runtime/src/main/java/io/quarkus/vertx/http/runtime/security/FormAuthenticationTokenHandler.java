package io.quarkus.vertx.http.runtime.security;

import static io.quarkus.security.spi.runtime.FormAuthenticationTokenSender.EMAIL_ATTRIBUTE_KEY;

import java.security.SecureRandom;
import java.util.Arrays;

import jakarta.enterprise.event.Event;

import org.jboss.logging.Logger;

import io.quarkus.arc.ClientProxy;
import io.quarkus.runtime.util.HashUtil;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.spi.runtime.FormAuthenticationTokenSender;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.security.form.token.FormAuthenticationTokenStorage;
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
    private final PersistentLoginManager loginManager;
    private final SecureRandom secureRandom;
    private final String cookieName;
    private final String usernameParameter;
    private final int tokenLength;
    private final FormAuthenticationTokenStorage tokenStorage;

    private FormAuthenticationTokenHandler(FormAuthenticationTokenSender tokenSender, String postTokenGenerationLocation,
            String tokenFormParameter, Event<FormAuthenticationEvent> formAuthEvent, PersistentLoginManager loginManager,
            String cookieName, String usernameParameter, int tokenLength, FormAuthenticationTokenStorage tokenStorage) {
        this.tokenSender = tokenSender;
        this.postTokenGenerationLocation = postTokenGenerationLocation;
        this.tokenFormParameter = tokenFormParameter;
        this.formAuthEvent = formAuthEvent;
        this.loginManager = loginManager;
        this.cookieName = cookieName;
        this.usernameParameter = usernameParameter;
        this.tokenLength = tokenLength;
        this.tokenStorage = tokenStorage;
        this.secureRandom = new SecureRandom();
    }

    Uni<SecurityIdentity> authenticateUsingToken(String token, IdentityProviderManager identityProviderManager,
            RoutingContext routingContext) {
        // FIXME: decrypt token!! salt!
        // FIXME: decode token -> if not possible then completion exception
        // FIXME: decoded token -> validate timestamp, and use username to authenticate
        // FIXME: remove cookie!!!!!!

        String principal = null; // FIXME: impl. me1
        return findSecurityIdentityByPrincipalName(identityProviderManager, routingContext, principal);
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
                        return;
                    }

                    char[] token = generateToken();
                    String tokenHash = sha512(token); // TODO: ideally don't store this in env var
                    // TODO: store as cookie
                    // TODO: I'd like this cookie to use different enc key or be more random, maybe just a hash?
                    //      the issue is that we just give it anyone, regardless whether the user exists or not!
                    //      should be go to the database instead first, after all??? probably no!
                    //      MAYBE WE SHOULD ENCRYPT IT TWICE, once with the token, second time with the enc key!!
                    //      this way, users can only get take on our enc key if they have the token
                    //      that is, if they received email because they were in the database!!!
                    // FIXME: the token may only be stored as a hashcode in the cookie!!
                    // FIXME: limit TTL for the cookie validity, possibly make it configurable and default should be 6 minutes
                    sendToken(token, jUsername, identityProviderManager, context);
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

    private void sendToken(char[] token, String principalName, IdentityProviderManager identityProviderManager,
            RoutingContext context) {
        // this must be asynchronous, so that we don't signal by the response time if the principal name exists
        findSecurityIdentityByPrincipalName(identityProviderManager, context, principalName)
                .map(securityIdentity -> {
                    if (securityIdentity == null) {
                        throw new AuthenticationCompletionException(
                                "Cannot find SecurityIdentity for principal name " + principalName);
                    }
                    String emailAddress = securityIdentity.getAttribute(EMAIL_ATTRIBUTE_KEY);
                    if (emailAddress == null || emailAddress.isBlank()) {
                        throw new AuthenticationCompletionException(
                                "SecurityIdentity must have attribute '%s' with email address".formatted(EMAIL_ATTRIBUTE_KEY));
                    }
                    return emailAddress;
                })
                .flatMap(emailAddress -> tokenSender.sendToken(token, emailAddress))
                .subscribe().with(onTokenSent -> {
                    // FIXME: possibly tracing log message, also fire event
                    Arrays.fill(token, '0');
                },
                        failure -> {
                            // FIXME: LOG IT, possibly fire event (the same as above but with failure???)
                        });
        // TODO: get email by retrieving the security identity first!
        // FIXME: impl. me!
        // FIXME: maybe, the token should be used as enc key for the cookie, so that we can only decrypt it using it?
        //      or maybe, some combination with enc key? yeah, it cannot be just the token because then users will
        //      be able to temper with it!!!
    }

    private char[] generateToken() {
        // this may seem like a lot, but since we don't have OTP brute-force protection, and we are reusing the session
        // enc key to encrypt cookie with the token request, and there is a chance that some users won't rotate enc key
        // we need high entropy in order to limit possibility that someone will succeed in brute-force attacks
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
            var aTokenStorage = tokenStorage == null ? new CookieFormAuthenticationTokenStorage() : tokenStorage;
            return new FormAuthenticationTokenHandler(tokenSender, tokenConfig.tokenPage().orElse(null),
                    tokenConfig.tokenParameter(), formAuthEvent, loginManager, tokenConfig.cookieName(),
                    runtimeForm.usernameParameter(), tokenConfig.tokenLength(), aTokenStorage);
        }
    }

    private static Uni<SecurityIdentity> findSecurityIdentityByPrincipalName(IdentityProviderManager identityProviderManager,
            RoutingContext routingContext, String principal) {
        return identityProviderManager.authenticate(HttpSecurityUtils
                .setRoutingContextAttribute(new TrustedAuthenticationRequest(principal), routingContext));
    }

    private static String sha512(char[] token) {
        // this is only safe for UTF-8 because we use only chars from SAFE_TOKEN_CHARS
        byte[] bytes = new byte[token.length];
        try {
            for (int i = 0; i < token.length; i++) {
                bytes[i] = (byte) token[i];
            }
            return HashUtil.sha512(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
