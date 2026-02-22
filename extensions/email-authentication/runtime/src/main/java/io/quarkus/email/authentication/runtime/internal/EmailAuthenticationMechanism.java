package io.quarkus.email.authentication.runtime.internal;

import static io.netty.handler.codec.http.HttpHeaderNames.LOCATION;
import static io.quarkus.email.authentication.runtime.internal.CookieEmailAuthenticationTokenStorage.addPersistentLoginManager;
import static io.quarkus.email.authentication.runtime.internal.CookieEmailAuthenticationTokenStorage.removePersistentLoginManager;
import static io.quarkus.email.authentication.runtime.internal.EmailAuthenticationEventImpl.createAuthenticationTokenEvent;
import static io.quarkus.email.authentication.runtime.internal.EmailAuthenticationEventImpl.createEmptyEvent;
import static io.quarkus.email.authentication.runtime.internal.EmailAuthenticationEventImpl.createLoginEvent;
import static io.quarkus.email.authentication.runtime.internal.EmailAuthenticationRecorder.LIVE_RELOAD_ENCRYPTION_KEY;
import static io.quarkus.security.spi.runtime.SecurityEventHelper.fire;
import static io.quarkus.security.spi.runtime.SecurityEventHelper.isEventObserved;
import static io.quarkus.vertx.http.runtime.security.HttpSecurityUtils.setRoutingContextAttribute;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.spi.BeanManager;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.email.authentication.EmailAuthenticationEvent;
import io.quarkus.email.authentication.EmailAuthenticationTokenSender;
import io.quarkus.email.authentication.EmailAuthenticationTokenStorage;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.AuthenticationException;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.runtime.SecurityConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.PersistentLoginManager;
import io.smallrye.common.vertx.VertxContext;
import io.smallrye.mutiny.Uni;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.CookieSameSite;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

final class EmailAuthenticationMechanism implements HttpAuthenticationMechanism {

    /**
     * Does not contain 0, O, 1, I, l to avoid confusion between number and lookalike letters.
     * Vowels (except Y) are removed as well to limit chance we get undesirable words (like rude words).
     */
    private static final String SAFE_TOKEN_CHARS = "23456789BCDFGHJKMNPQRSTVWXYZ";
    private static final String EMAIL = "email";
    private static final Logger LOG = Logger.getLogger(EmailAuthenticationMechanism.class);

    private final String loginPage;
    private final String errorPage;
    private final String postLocation;
    private final String locationCookie;
    private final String landingPage;
    private final CookieSameSite cookieSameSite;
    private final String cookiePath;
    private final String cookieDomain;
    private final PersistentLoginManager loginManager;
    private final Event<EmailAuthenticationEvent> emailAuthEvent;
    private final int priority;
    private final EmailAuthenticationTokenSender tokenSender;
    private final EmailAuthenticationTokenStorage tokenStorage;
    private final SecureRandom secureRandom;
    private final String postTokenGenerationLocation;
    private final String usernameParameter;
    private final String tokenParameter;
    private final int tokenLength;
    private final String tokenGenerationLocation;

    EmailAuthenticationMechanism(EmailAuthenticationConfig emailAuthenticationConfig, VertxHttpConfig vertxHttpConfig,
            EmailAuthenticationTokenSender tokenSender, EmailAuthenticationTokenStorage tokenStorage,
            @ConfigProperty(name = LIVE_RELOAD_ENCRYPTION_KEY) Optional<String> liveReloadEncryptionKey,
            BeanManager beanManager, Event<EmailAuthenticationEvent> emailAuthEvent, SecurityConfig securityConfig) {
        this.secureRandom = new SecureRandom();
        this.loginManager = new PersistentLoginManager(getEncryptionKey(vertxHttpConfig, liveReloadEncryptionKey),
                emailAuthenticationConfig.sessionCookie(), emailAuthenticationConfig.timeout().toMillis(),
                emailAuthenticationConfig.newSessionCookieInterval().toMillis(), emailAuthenticationConfig.httpOnlyCookie(),
                emailAuthenticationConfig.cookieSameSite().name(), emailAuthenticationConfig.cookiePath().orElse(null),
                emailAuthenticationConfig.sessionCookieMaxAge().map(Duration::toSeconds).orElse(-1L),
                emailAuthenticationConfig.cookieDomain().orElse(null));
        this.loginPage = startWithSlash(emailAuthenticationConfig.loginPage().orElse(null));
        this.errorPage = startWithSlash(emailAuthenticationConfig.errorPage().orElse(null));
        this.landingPage = startWithSlash(emailAuthenticationConfig.landingPage().orElse(null));
        this.postLocation = startWithSlash(emailAuthenticationConfig.postLocation());
        this.locationCookie = emailAuthenticationConfig.locationCookie();
        this.cookiePath = emailAuthenticationConfig.cookiePath().orElse(null);
        this.cookieDomain = emailAuthenticationConfig.cookieDomain().orElse(null);
        this.cookieSameSite = CookieSameSite.valueOf(emailAuthenticationConfig.cookieSameSite().name());
        this.emailAuthEvent = isEventObserved(createEmptyEvent(), beanManager, securityConfig.events().enabled())
                ? emailAuthEvent
                : null;
        this.priority = emailAuthenticationConfig.priority();
        this.tokenSender = tokenSender;
        this.tokenStorage = tokenStorage;
        this.postTokenGenerationLocation = emailAuthenticationConfig.tokenPage().orElse(null);
        this.usernameParameter = emailAuthenticationConfig.usernameParameter();
        this.tokenParameter = emailAuthenticationConfig.tokenParameter();
        this.tokenLength = emailAuthenticationConfig.tokenLength();
        this.tokenGenerationLocation = emailAuthenticationConfig.tokenGenerationLocation();
    }

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (isPostLocation(context)) {
            //we always re-auth if it is a post to the auth URL
            context.put(HttpAuthenticationMechanism.class.getName(), this);
            return runFormAuth(context, identityProviderManager);
        } else if (isTokenGenerationPath(context)) {
            return generateAndSendToken(context, identityProviderManager).map(ignored -> {
                if (context.response().ended() || context.failed()) {
                    // just to stay safe; we recommend to return Uni failure if the request to send the token was rejected
                    return null;
                }
                if (postTokenGenerationLocation == null) {
                    context.response().setStatusCode(200);
                    context.response().end();
                } else {
                    String location = assembleRedirectLocation(context, postTokenGenerationLocation);
                    context.response().setStatusCode(302);
                    context.response().headers().add(LOCATION, location);
                    context.response().end();
                }
                return (SecurityIdentity) null;
            }).onFailure(f -> !(f instanceof AuthenticationException)).transform(AuthenticationFailedException::new);
        } else {
            PersistentLoginManager.RestoreResult result = loginManager.restore(context);
            if (result != null) {
                context.put(HttpAuthenticationMechanism.class.getName(), this);
                return findSecurityIdentityByPrincipalName(identityProviderManager, context, result.getPrincipal())
                        .invoke(securityIdentity -> {
                            LOG.tracef("Authenticated user with principal name '%s' using the session cookie",
                                    result.getPrincipal());
                            loginManager.save(securityIdentity, context, result, context.request().isSSL());
                        })
                        .onFailure().invoke(f -> {
                            LOG.debugf(f, "Could not find valid SecurityIdentity for principal name '%s'",
                                    result.getPrincipal());
                            loginManager.clear(context);
                        });
            }
            return Uni.createFrom().nullItem();
        }
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        if (isPostLocation(context)) {
            if (errorPage != null) {
                LOG.debugf("Serving email authentication error page %s for %s", errorPage, context);
                // This method would no longer be called if authentication had already occurred.
                return getRedirect(context, errorPage);
            }
        } else if (isTokenGenerationPath(context)) {
            if (errorPage != null) {
                LOG.debugf("Serving email authentication error page %s for %s", errorPage, context.normalizedPath());
                return getRedirect(context, errorPage);
            }
        } else if (loginPage != null) {
            LOG.debugf("Serving email authentication login page %s for %s", loginPage, context);
            // we need to store the URL
            storeInitialLocation(context);
            return getRedirect(context, loginPage);
        }

        // redirect is disabled
        return Uni.createFrom().item(new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code()));
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(TrustedAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.POST, postLocation, EMAIL));
    }

    @Override
    public int getPriority() {
        return priority;
    }

    private boolean isPostLocation(RoutingContext context) {
        return context.normalizedPath().endsWith(postLocation) && context.request().method().equals(HttpMethod.POST);
    }

    private Uni<SecurityIdentity> runFormAuth(final RoutingContext exchange,
            final IdentityProviderManager securityContext) {
        exchange.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(uniEmitter -> {
            exchange.request().endHandler(ignored -> {
                try {
                    final String token = exchange.request().formAttributes().get(tokenParameter);
                    if (token == null || token.isEmpty()) {
                        LOG.debugf(
                                "Could not authenticate as email authentication token was not present in the request posted to '%s'",
                                postLocation);
                        uniEmitter.complete(null);
                        return;
                    }
                    authenticateUsingToken(token, securityContext, exchange)
                            .subscribe().with(identity -> {
                                fireEvent(createLoginEvent(identity, token, exchange));

                                try {
                                    loginManager.save(identity, exchange, null, exchange.request().isSSL());
                                    if (landingPage != null || exchange.request().getCookie(locationCookie) != null) {
                                        handleRedirectBack(exchange);
                                        //we  have authenticated, but we want to just redirect back to the original page
                                        //so we don't actually authenticate the current request
                                        //instead we have just set a cookie so the redirected request will be authenticated
                                    } else {
                                        exchange.response().setStatusCode(200);
                                        exchange.response().end();
                                    }
                                    uniEmitter.complete(null);
                                } catch (Throwable t) {
                                    LOG.error("Unable to complete email authentication", t);
                                    uniEmitter.fail(t);
                                }
                            }, uniEmitter::fail);
                } catch (Throwable t) {
                    uniEmitter.fail(t);
                }
            });
            exchange.request().resume();
        });
    }

    private void handleRedirectBack(final RoutingContext exchange) {
        Cookie redirect = exchange.request().getCookie(locationCookie);
        String location;
        if (redirect != null) {
            verifyRedirectBackLocation(exchange.request().absoluteURI(), redirect.getValue());
            redirect.setSecure(exchange.request().isSSL());
            redirect.setSameSite(cookieSameSite);
            location = redirect.getValue();
            exchange.response().addCookie(redirect.setMaxAge(0));
        } else {
            location = assembleRedirectLocation(exchange, landingPage);
        }
        exchange.response().setStatusCode(302);
        exchange.response().headers().add(LOCATION, location);
        exchange.response().end();
    }

    private void verifyRedirectBackLocation(String requestURIString, String redirectUriString) {
        URI requestUri = URI.create(requestURIString);
        URI redirectUri = URI.create(redirectUriString);
        if (!requestUri.getAuthority().equals(redirectUri.getAuthority())
                || !requestUri.getScheme().equals(redirectUri.getScheme())) {
            LOG.errorf("Location cookie value %s does not match the current request URI %s's scheme, host or port",
                    redirectUriString, requestURIString);
            throw new AuthenticationCompletionException();
        }
    }

    private void storeInitialLocation(final RoutingContext exchange) {
        Cookie cookie = Cookie.cookie(locationCookie, exchange.request().absoluteURI())
                .setPath(cookiePath).setSameSite(cookieSameSite).setSecure(exchange.request().isSSL());
        if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
        }
        exchange.response().addCookie(cookie);
    }

    private Uni<SecurityIdentity> authenticateUsingToken(String token, IdentityProviderManager identityProviderManager,
            RoutingContext routingContext) {
        // allows the default token storage, which based on cookies, to reuse our login manager
        addPersistentLoginManager(routingContext, loginManager);

        return tokenStorage.findPrincipalNameByToken(token, routingContext)
                .flatMap(principalName -> {
                    removePersistentLoginManager(routingContext);
                    if (principalName == null || principalName.isEmpty()) {
                        return Uni.createFrom().failure(new AuthenticationFailedException(
                                "Cannot authentication with unknown or invalid token: " + token));
                    }
                    LOG.debugf("Found principal name '%s' for email authentication token '%s'", principalName, token);
                    return findSecurityIdentityByPrincipalName(identityProviderManager, routingContext, principalName)
                            .onFailure().invoke(f -> LOG.debugf(f, "Could not find SecurityIdentity with principal name '%s' " +
                                    "(the principal name resolved for email authentication token '%s')", principalName, token));
                });
    }

    private boolean isTokenGenerationPath(RoutingContext context) {
        return context.normalizedPath().endsWith(tokenGenerationLocation) && context.request().method().equals(HttpMethod.POST);
    }

    private Uni<Void> generateAndSendToken(RoutingContext context, IdentityProviderManager identityProviderManager) {
        context.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(uniEmitter -> {
            context.request().endHandler(ignored -> {
                try {
                    String username = context.request().formAttributes().get(usernameParameter);
                    if (username == null || username.isEmpty()) {
                        LOG.debugf("Could not send token as form attribute '%s' was not present in the posted result for %s",
                                usernameParameter, context);
                        uniEmitter.fail(new IllegalArgumentException("Form attribute '" + usernameParameter
                                + "' is required for the POST path '" + tokenGenerationLocation + "'"));
                    } else {
                        // token is generated lazily by design, since generating random is not cheap operation;
                        // the storage may decide to reject the incoming request based on username, IP, rate limit, ...
                        var tokenRequest = new EmailAuthenticationTokenStorage.EmailAuthenticationTokenRequest() {

                            private volatile char[] generatedToken = null;

                            @Override
                            public char[] token() {
                                if (generatedToken == null) {
                                    generatedToken = generateToken();
                                }
                                return generatedToken;
                            }
                        };

                        addPersistentLoginManager(context, loginManager);
                        tokenStorage.storeToken(tokenRequest, username, context).subscribe().with(
                                ignored2 -> {
                                    removePersistentLoginManager(context);

                                    if (tokenRequest.generatedToken == null) {
                                        LOG.warnf("Email authentication token storage did not store token requested for "
                                                + "username '%s'; storage must return failure for rejected requests", username);
                                        uniEmitter.fail(new IllegalStateException(
                                                "Email authentication token storage did not store the token"));
                                    } else {
                                        LOG.debugf("Stored token for the token request with username '%s'", username);
                                        sendToken(tokenRequest.generatedToken, username, identityProviderManager, context);
                                        uniEmitter.complete(null);
                                    }
                                },
                                failure -> {
                                    removePersistentLoginManager(context);
                                    LOG.debugf(failure,
                                            "Failed to store email authentication token requested for username '%s'", username);
                                    fireEvent(createAuthenticationTokenEvent(failure, username, context));
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
            RoutingContext event) {
        // this must be asynchronous, so that we don't signal by the response time if the principal name exists
        // the incoming HTTP request is closed right after calling this method, therefore we run this on a nested context
        var nestedContext = VertxContext.newNestedContext(event.vertx().getOrCreateContext());
        findSecurityIdentityByPrincipalName(identityProviderManager, event, principalName)
                .flatMap(securityIdentity -> tokenSender.sendToken(token, securityIdentity).replaceWith(securityIdentity))
                .runSubscriptionOn(command -> nestedContext.runOnContext(unused -> command.run()))
                .subscribe().with(identity -> {
                    LOG.debugf("Sent token to SecurityIdentity with principal name '%s'", identity.getPrincipal().getName());
                    fireEvent(createAuthenticationTokenEvent(identity, principalName, token, event),
                            () -> Arrays.fill(token, '0'));
                },
                        failure -> {
                            LOG.debugf(failure,
                                    "Failed to send email authentication token '%s' generated for principal name '%s'",
                                    new String(token), principalName);
                            fireEvent(createAuthenticationTokenEvent(failure, principalName, event));
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

    private void fireEvent(EmailAuthenticationEvent eventInstance) {
        fireEvent(eventInstance, null);
    }

    private void fireEvent(EmailAuthenticationEvent eventInstance, Runnable onFired) {
        if (emailAuthEvent != null) {
            if (onFired != null) {
                fire(emailAuthEvent, eventInstance).whenComplete((e, t) -> onFired.run());
            } else {
                fire(emailAuthEvent, eventInstance);
            }
        }
    }

    private static String startWithSlash(String page) {
        if (page == null) {
            return null;
        }
        return page.startsWith("/") ? page : "/" + page;
    }

    private static String assembleRedirectLocation(RoutingContext exchange, String path) {
        return exchange.request().scheme() + "://" + exchange.request().authority() + path;
    }

    private static Uni<ChallengeData> getRedirect(final RoutingContext exchange, final String location) {
        String loc = assembleRedirectLocation(exchange, location);
        return Uni.createFrom().item(new ChallengeData(302, LOCATION, loc));
    }

    private static Uni<SecurityIdentity> findSecurityIdentityByPrincipalName(IdentityProviderManager identityProviderManager,
            RoutingContext routingContext, String principal) {
        return identityProviderManager
                .authenticate(setRoutingContextAttribute(new TrustedAuthenticationRequest(principal), routingContext));
    }

    private static String getEncryptionKey(VertxHttpConfig vertxHttpConfig, Optional<String> liveReloadEncryptionKey) {
        return vertxHttpConfig.encryptionKey().orElseGet(() -> {
            var key = liveReloadEncryptionKey.orElseGet(EmailAuthenticationRecorder::generateEncryptionKey);
            LOG.warn("Encryption key was not specified for persistent Email authentication, using temporary key " + key);
            return key;
        });
    }
}
