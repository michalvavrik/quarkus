package io.quarkus.vertx.http.runtime.security;

import static io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism.getRedirect;
import static io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism.handleRedirectBack;
import static io.quarkus.vertx.http.runtime.security.HttpCredentialTransport.Type.POST;
import static io.quarkus.vertx.http.runtime.security.HttpSecurityUtils.setRoutingContextAttribute;
import static io.quarkus.vertx.http.runtime.security.RoutingContextAwareSecurityIdentity.addRoutingCtxToIdentityIfMissing;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import org.jboss.logging.Logger;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniEmitter;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.CookieSameSite;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/**
 * This class is not part of public API, and it can change whenever needed.
 */
public final class FormTokenAuthenticationMechanism implements HttpAuthenticationMechanism {

    public static final String FORM_TOKEN = "form-token";
    private static final Logger LOG = Logger.getLogger(FormTokenAuthenticationMechanism.class);
    private static final String COOKIE_NAME = "io.quarkus.vertx.http.runtime.security.form-token.cookie-name";
    private static final String COOKIE_PATH = "io.quarkus.vertx.http.runtime.security.form-token.cookie-path";
    /**
     * Temporary encryption key, persistent across DEV mode restarts.
     */
    private static volatile String encryptionKey;
    private final String postLocation;
    private final String loginPage;
    private final String errorPage;
    private final String landingPage;
    private final String locationCookie;
    private final String cookieDomain;
    private final String cookiePath;
    private final CookieSameSite cookieSameSite;
    private final boolean httpOnlyCookie;
    private final PersistentLoginManager loginManager;
    private final String tokenRequestPath;
    private final String tokenParam;

    public FormTokenAuthenticationMechanism(FormAuthenticationToken config, Optional<String> encKey) {
        final String key;
        if (encKey.isEmpty()) {
            if (encryptionKey != null) {
                // persist across dev mode restarts
                key = encryptionKey;
            } else {
                byte[] data = new byte[32];
                new SecureRandom().nextBytes(data);
                key = encryptionKey = Base64.getEncoder().encodeToString(data);
                LOG.warn("Encryption key was not specified for persistent form token auth, using temporary key " + key);
            }
        } else {
            key = encKey.get();
        }
        this.postLocation = config.postLocation();
        this.loginPage = config.loginPage().orElse(null);
        this.errorPage = config.errorPage().orElse(null);
        this.locationCookie = config.locationCookie();
        this.cookieDomain = config.cookieDomain().orElse(null);
        this.cookiePath = config.cookiePath().orElse(null);
        this.cookieSameSite = CookieSameSite.valueOf(config.cookieSameSite().name());
        this.httpOnlyCookie = config.httpOnlyCookie();
        this.loginManager = new PersistentLoginManager(key, config.cookieName(), config.timeout().toMillis(),
                config.newCookieInterval().toMillis(), config.httpOnlyCookie(), config.cookieSameSite().name(),
                config.cookiePath().orElse(null), config.cookieMaxAge().map(Duration::toSeconds).orElse(-1L),
                config.cookieDomain().orElse(null));
        this.tokenRequestPath = config.tokenRequestPath();
        this.tokenParam = config.parameterName();
        this.landingPage = config.landingPage().orElse(null);
    }

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (isPostLocation(context)) {
            //we always re-auth if it is a post to the auth URL
            context.put(HttpAuthenticationMechanism.class.getName(), this);
            return runFormAuth(context, identityProviderManager)
                    .onItem().ifNotNull().transform(new Function<SecurityIdentity, SecurityIdentity>() {
                        @Override
                        public SecurityIdentity apply(SecurityIdentity identity) {
                            // used for logout
                            context.put(COOKIE_NAME, loginManager.getCookieName());
                            context.put(COOKIE_PATH, cookiePath);
                            return addRoutingCtxToIdentityIfMissing(identity, context);
                        }
                    });
        } else if (isTokenRequestPath(context)) {
            // FIXME: EITHER GENERATE THE TOKEN, send and redirect, or if invalid (or too many), respond with 401? hard to say
            // FIXME: assure that both post location and the token request path are required to be redirected here, that is - authenticated
        } else {
            PersistentLoginManager.RestoreResult result = loginManager.restore(context);
            if (result != null) {
                context.put(HttpAuthenticationMechanism.class.getName(), this);
                return identityProviderManager
                        .authenticate(
                                setRoutingContextAttribute(new TrustedAuthenticationRequest(result.getPrincipal()), context))
                        .onItem().ifNotNull().transform(new Function<SecurityIdentity, SecurityIdentity>() {
                            @Override
                            public SecurityIdentity apply(SecurityIdentity identity) {
                                loginManager.save(identity, context, result, context.request().isSSL());
                                // used for logout
                                context.put(COOKIE_NAME, loginManager.getCookieName());
                                context.put(COOKIE_PATH, cookiePath);
                                return addRoutingCtxToIdentityIfMissing(identity, context);
                            }
                        });
            }
        }
        return Uni.createFrom().nullItem();
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        if (isPostLocation(context)) {
            if (errorPage != null) {
                LOG.debugf("Serving form auth error page %s for %s", errorPage, context);
                // This method would no longer be called if authentication had already occurred.
                return getRedirect(context, errorPage);
            }
        } else if (loginPage != null) {
            LOG.debugf("Serving login form %s for %s", loginPage, context);
            // we need to store the URL
            storeInitialLocation(context);
            return getRedirect(context, loginPage);
        }

        // redirect is disabled
        return Uni.createFrom().item(new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code(), null, null));
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(TrustedAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(POST, postLocation, FORM_TOKEN));
    }

    private void storeInitialLocation(RoutingContext routingContext) {
        Cookie cookie = Cookie.cookie(locationCookie, routingContext.request().absoluteURI()).setHttpOnly(httpOnlyCookie)
                .setPath(cookiePath).setSameSite(cookieSameSite).setSecure(routingContext.request().isSSL());
        if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
        }
        routingContext.response().addCookie(cookie);
    }

    private boolean isPostLocation(RoutingContext context) {
        return context.normalizedPath().endsWith(postLocation) && HttpMethod.POST.equals(context.request().method());
    }

    private boolean isTokenRequestPath(RoutingContext context) {
        return context.normalizedPath().endsWith(tokenRequestPath) && HttpMethod.POST.equals(context.request().method());
    }

    private Uni<SecurityIdentity> runFormAuth(final RoutingContext exchange,
            final IdentityProviderManager securityContext) {
        exchange.request().setExpectMultipart(true);
        return Uni.createFrom().emitter(new Consumer<UniEmitter<? super SecurityIdentity>>() {
            @Override
            public void accept(UniEmitter<? super SecurityIdentity> uniEmitter) {
                exchange.request().endHandler(new Handler<Void>() {
                    @Override
                    public void handle(Void event) {
                        try {
                            final String jToken = exchange.request().getFormAttribute(tokenParam);
                            if (jToken == null || jToken.isBlank()) {
                                LOG.debugf("Could not authenticate as token was not present in the posted result for %s",
                                        exchange);
                                uniEmitter.complete(null);
                                return;
                            }
                            final String principal = null; // FIXME: impl. me!
                            securityContext
                                    .authenticate(
                                            setRoutingContextAttribute(new TrustedAuthenticationRequest(principal), exchange))
                                    .subscribe().with(new Consumer<SecurityIdentity>() {
                                        @Override
                                        public void accept(SecurityIdentity identity) {
                                            try {
                                                loginManager.save(identity, exchange, null, exchange.request().isSSL());
                                                if (landingPage != null
                                                        || exchange.request().getCookie(locationCookie) != null) {
                                                    handleRedirectBack(exchange, locationCookie, cookieSameSite, landingPage);
                                                    //we  have authenticated, but we want to just redirect back to the original page
                                                    //so we don't actually authenticate the current request
                                                    //instead we have just set a cookie so the redirected request will be authenticated
                                                } else {
                                                    exchange.response().setStatusCode(200);
                                                    exchange.response().end();
                                                }
                                                uniEmitter.complete(null);
                                            } catch (Throwable t) {
                                                LOG.error("Unable to complete post authentication", t);
                                                uniEmitter.fail(t);
                                            }
                                        }
                                    }, new Consumer<Throwable>() {
                                        @Override
                                        public void accept(Throwable throwable) {
                                            uniEmitter.fail(throwable);
                                        }
                                    });
                        } catch (Throwable t) {
                            uniEmitter.fail(t);
                        }
                    }
                });
                exchange.request().resume();
            }
        });
    }
}
