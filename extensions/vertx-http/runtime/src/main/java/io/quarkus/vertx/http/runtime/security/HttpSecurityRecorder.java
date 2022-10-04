package io.quarkus.vertx.http.runtime.security;

import static io.quarkus.vertx.http.runtime.security.DefaultAuthFailureHandlerEndStrategy.DEFAULT_AUTH_FAILURE_HANDLER_END_STRATEGY;
import static io.quarkus.vertx.http.runtime.security.DefaultAuthFailureHandlerEndStrategy.END;
import static io.quarkus.vertx.http.runtime.security.DefaultAuthFailureHandlerEndStrategy.NEXT_FAILURE_HANDLER;
import static java.lang.Boolean.parseBoolean;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.enterprise.inject.spi.CDI;

import org.jboss.logging.Logger;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.arc.runtime.BeanContainerListener;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.AuthenticationRedirectException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.HttpConfiguration;
import io.smallrye.mutiny.CompositeException;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniSubscriber;
import io.smallrye.mutiny.subscription.UniSubscription;
import io.smallrye.mutiny.tuples.Functions;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class HttpSecurityRecorder {

    private static final Logger log = Logger.getLogger(HttpSecurityRecorder.class);
    protected static final Consumer<Throwable> NOOP_CALLBACK = new Consumer<Throwable>() {
        @Override
        public void accept(Throwable throwable) {

        }
    };

    final RuntimeValue<HttpConfiguration> httpConfiguration;
    final HttpBuildTimeConfig buildTimeConfig;

    //the temp encryption key, persistent across dev mode restarts
    static volatile String encryptionKey;

    public HttpSecurityRecorder(RuntimeValue<HttpConfiguration> httpConfiguration, HttpBuildTimeConfig buildTimeConfig) {
        this.httpConfiguration = httpConfiguration;
        this.buildTimeConfig = buildTimeConfig;
    }

    public Handler<RoutingContext> authenticationMechanismHandler(boolean proactiveAuthentication) {
        return new Handler<RoutingContext>() {

            volatile HttpAuthenticator authenticator;

            @Override
            public void handle(RoutingContext event) {
                if (authenticator == null) {
                    authenticator = CDI.current().select(HttpAuthenticator.class).get();
                }
                //we put the authenticator into the routing context so it can be used by other systems
                event.put(HttpAuthenticator.class.getName(), authenticator);

                //register the default auth failure handler
                //if proactive auth is used this is the only one
                //if using lazy auth this can be modified downstream, to control authentication behaviour
                event.put(QuarkusHttpUser.AUTH_FAILURE_HANDLER, new BiConsumer<RoutingContext, Throwable>() {

                    private final DefaultAuthFailureHandlerEndStrategyExec endStrategyExec = new DefaultAuthFailureHandlerEndStrategyExec(
                            event);

                    @Override
                    public void accept(RoutingContext routingContext, Throwable throwable) {

                        if (endStrategyExec.preventRepeating()) {
                            // we have already handled event here
                            // this might happen f.e. when we failed event here with the same throwable as we accepted
                            // in order to pass the throwable to failure handlers
                            return;
                        }

                        throwable = extractRootCause(throwable);
                        //auth failed
                        if (throwable instanceof AuthenticationFailedException) {
                            final AuthenticationFailedException authenticationFailedException = (AuthenticationFailedException) throwable;
                            authenticator.sendChallenge(event).subscribe().with(new Consumer<Boolean>() {
                                @Override
                                public void accept(Boolean aBoolean) {
                                    endStrategyExec.proceed(authenticationFailedException);
                                }
                            }, new Consumer<Throwable>() {
                                @Override
                                public void accept(Throwable throwable) {
                                    event.fail(throwable);
                                }
                            });
                        } else if (throwable instanceof AuthenticationCompletionException) {
                            log.debug("Authentication has failed, returning HTTP status 401");
                            event.response().setStatusCode(401);
                            event.response().end();
                        } else if (throwable instanceof AuthenticationRedirectException) {
                            AuthenticationRedirectException redirectEx = (AuthenticationRedirectException) throwable;
                            event.response().setStatusCode(redirectEx.getCode());
                            event.response().headers().set(HttpHeaders.LOCATION, redirectEx.getRedirectUri());
                            event.response().headers().set(HttpHeaders.CACHE_CONTROL, "no-store");
                            event.response().headers().set("Pragma", "no-cache");
                            event.response().end();
                        } else {
                            event.fail(throwable);
                        }
                    }

                });

                if (proactiveAuthentication) {
                    Uni<SecurityIdentity> potentialUser = authenticator.attemptAuthentication(event).memoize().indefinitely();
                    potentialUser
                            .subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                                @Override
                                public void onSubscribe(UniSubscription subscription) {

                                }

                                @Override
                                public void onItem(SecurityIdentity identity) {
                                    if (event.response().ended()) {
                                        return;
                                    }
                                    if (identity == null) {
                                        Uni<SecurityIdentity> anon = authenticator.getIdentityProviderManager()
                                                .authenticate(AnonymousAuthenticationRequest.INSTANCE);
                                        anon.subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                                            @Override
                                            public void onSubscribe(UniSubscription subscription) {

                                            }

                                            @Override
                                            public void onItem(SecurityIdentity item) {
                                                event.put(QuarkusHttpUser.DEFERRED_IDENTITY_KEY, anon);
                                                event.setUser(new QuarkusHttpUser(item));
                                                event.next();
                                            }

                                            @Override
                                            public void onFailure(Throwable failure) {
                                                BiConsumer<RoutingContext, Throwable> handler = event
                                                        .get(QuarkusHttpUser.AUTH_FAILURE_HANDLER);
                                                if (handler != null) {
                                                    handler.accept(event, failure);
                                                }
                                            }
                                        });
                                    } else {//when the result is evaluated we set the user, even if it is evaluated lazily
                                        event.setUser(new QuarkusHttpUser(identity));
                                        event.put(QuarkusHttpUser.DEFERRED_IDENTITY_KEY, potentialUser);
                                        event.next();
                                    }
                                }

                                @Override
                                public void onFailure(Throwable failure) {
                                    //this can be customised
                                    BiConsumer<RoutingContext, Throwable> handler = event
                                            .get(QuarkusHttpUser.AUTH_FAILURE_HANDLER);
                                    if (handler != null) {
                                        handler.accept(event, failure);
                                    }

                                }
                            });
                } else {

                    Uni<SecurityIdentity> lazyUser = Uni
                            .createFrom()
                            .nullItem()
                            // Only attempt to authenticate if required
                            .flatMap(n -> authenticator.attemptAuthentication(event))
                            .memoize()
                            .indefinitely()
                            .flatMap(new Function<SecurityIdentity, Uni<? extends SecurityIdentity>>() {
                                @Override
                                public Uni<? extends SecurityIdentity> apply(SecurityIdentity securityIdentity) {
                                    //if it is null we use the anonymous identity
                                    if (securityIdentity == null) {
                                        return authenticator.getIdentityProviderManager()
                                                .authenticate(AnonymousAuthenticationRequest.INSTANCE);
                                    }
                                    return Uni.createFrom().item(securityIdentity);
                                }
                            }).onTermination().invoke(new Functions.TriConsumer<SecurityIdentity, Throwable, Boolean>() {
                                @Override
                                public void accept(SecurityIdentity identity, Throwable throwable, Boolean aBoolean) {
                                    if (identity != null) {
                                        //when the result is evaluated we set the user, even if it is evaluated lazily
                                        if (identity != null) {
                                            event.setUser(new QuarkusHttpUser(identity));
                                        }
                                    } else if (throwable != null) {
                                        //handle the auth failure
                                        //this can be customised
                                        BiConsumer<RoutingContext, Throwable> handler = event
                                                .get(QuarkusHttpUser.AUTH_FAILURE_HANDLER);
                                        if (handler != null) {
                                            handler.accept(event, throwable);
                                        }
                                    }
                                }
                            }).memoize().indefinitely();
                    event.put(QuarkusHttpUser.DEFERRED_IDENTITY_KEY, lazyUser);
                    event.next();
                }
            }
        };
    }

    private Throwable extractRootCause(Throwable throwable) {
        while ((throwable instanceof CompletionException && throwable.getCause() != null) ||
                (throwable instanceof CompositeException)) {
            if (throwable instanceof CompositeException) {
                throwable = ((CompositeException) throwable).getCauses().get(0);
            } else {
                throwable = throwable.getCause();
            }
        }
        return throwable;
    }

    public Handler<RoutingContext> permissionCheckHandler() {
        return new Handler<RoutingContext>() {
            volatile HttpAuthorizer authorizer;

            @Override
            public void handle(RoutingContext event) {
                if (authorizer == null) {
                    authorizer = CDI.current().select(HttpAuthorizer.class).get();
                }
                authorizer.checkPermission(event);
            }
        };
    }

    public BeanContainerListener initPermissions(HttpBuildTimeConfig permissions,
            Map<String, Supplier<HttpSecurityPolicy>> policies) {
        return new BeanContainerListener() {
            @Override
            public void created(BeanContainer container) {
                container.instance(PathMatchingHttpSecurityPolicy.class).init(permissions, policies);
            }
        };
    }

    public Supplier<FormAuthenticationMechanism> setupFormAuth() {

        return new Supplier<FormAuthenticationMechanism>() {
            @Override
            public FormAuthenticationMechanism get() {
                String key;
                if (!httpConfiguration.getValue().encryptionKey.isPresent()) {
                    if (encryptionKey != null) {
                        //persist across dev mode restarts
                        key = encryptionKey;
                    } else {
                        byte[] data = new byte[32];
                        new SecureRandom().nextBytes(data);
                        key = encryptionKey = Base64.getEncoder().encodeToString(data);
                        log.warn("Encryption key was not specified for persistent FORM auth, using temporary key " + key);
                    }
                } else {
                    key = httpConfiguration.getValue().encryptionKey.get();
                }
                FormAuthConfig form = buildTimeConfig.auth.form;
                PersistentLoginManager loginManager = new PersistentLoginManager(key, form.cookieName, form.timeout.toMillis(),
                        form.newCookieInterval.toMillis(), form.httpOnlyCookie);
                String loginPage = form.loginPage.startsWith("/") ? form.loginPage : "/" + form.loginPage;
                String errorPage = form.errorPage.startsWith("/") ? form.errorPage : "/" + form.errorPage;
                String landingPage = form.landingPage.startsWith("/") ? form.landingPage : "/" + form.landingPage;
                String postLocation = form.postLocation.startsWith("/") ? form.postLocation : "/" + form.postLocation;
                String usernameParameter = form.usernameParameter;
                String passwordParameter = form.passwordParameter;
                String locationCookie = form.locationCookie;
                boolean redirectAfterLogin = form.redirectAfterLogin;
                return new FormAuthenticationMechanism(loginPage, postLocation, usernameParameter, passwordParameter,
                        errorPage, landingPage, redirectAfterLogin, locationCookie, loginManager);
            }
        };
    }

    public Supplier<?> setupBasicAuth(HttpBuildTimeConfig buildTimeConfig) {
        return new Supplier<BasicAuthenticationMechanism>() {
            @Override
            public BasicAuthenticationMechanism get() {
                return new BasicAuthenticationMechanism(buildTimeConfig.auth.realm.orElse(null),
                        buildTimeConfig.auth.form.enabled);
            }
        };
    }

    public Supplier<?> setupMtlsClientAuth() {
        return new Supplier<MtlsAuthenticationMechanism>() {
            @Override
            public MtlsAuthenticationMechanism get() {
                return new MtlsAuthenticationMechanism();
            }
        };
    }

    /**
     * This handler resolves the identity, and will be mapped to the post location. Otherwise,
     * for lazy auth the post will not be evaluated if there is no security rule for the post location.
     */
    public Handler<RoutingContext> formAuthPostHandler() {
        return new Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext event) {
                Uni<SecurityIdentity> user = event.get(QuarkusHttpUser.DEFERRED_IDENTITY_KEY);
                user.subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                    @Override
                    public void onSubscribe(UniSubscription uniSubscription) {

                    }

                    @Override
                    public void onItem(SecurityIdentity securityIdentity) {
                        event.next();
                    }

                    @Override
                    public void onFailure(Throwable throwable) {
                        event.fail(throwable);
                    }
                });
            }
        };
    }

    /**
     * Determines what should happen once the default auth failure handler finished.
     */
    private static final class DefaultAuthFailureHandlerEndStrategyExec {

        /**
         * Signal {@link AuthenticationFailedException} has already been handled here.
         */
        private static final String AUTH_FAILED_EX_HANDLED = QuarkusHttpUser.AUTH_FAILURE_HANDLER
                + ".handled.auth-failed-ex";

        private final RoutingContext event;

        private DefaultAuthFailureHandlerEndStrategyExec(RoutingContext event) {
            this.event = event;
        }

        boolean iterateNext() {
            if (event.failed()) {
                // Continue to next failure handler
                event.next();
                return true;
            }
            return false;
        }

        void proceed(AuthenticationFailedException authenticationFailedException) {
            if (!event.response().ended()) {
                switch (getEndStrategy()) {
                    case END:
                        event.end();
                        break;
                    case NEXT_FAILURE_HANDLER:
                        // if the event has failed, continue to next failure handler
                        // if not, fail the event and ensure the default failure handle is skipped
                        if (!iterateNext()) {
                            // 'sendChallenge' of the custom auth mechanism may end response, but
                            // if not, we want to keep it possibility for failure handlers down the stream
                            // to handle the exception; if the ex. is not handled elsewhere, QuarkusErrorHandler
                            // is supposed to return 401 with empty body and headers set by the 'sendChallenge'
                            event.put(AUTH_FAILED_EX_HANDLED, true);
                            event.fail(authenticationFailedException);
                        }
                        break;
                }
            }
        }

        boolean preventRepeating() {
            if (event.response().ended()) {
                return true;
            } else if (getEndStrategy() == NEXT_FAILURE_HANDLER && event.failure() instanceof AuthenticationFailedException
                    && parseBoolean(event.get(AUTH_FAILED_EX_HANDLED))) {
                // We have already handled this exception and know other failure handlers may want to modify the response.
                // This situation could happen if the default auth failure handler has been previously
                // invoked without failing the event (via routingContext.get(AUTH_FAILURE_HANDLER) ...).

                // Continue to next failure handler
                event.next();
                return true;
            }

            return false;
        }

        private DefaultAuthFailureHandlerEndStrategy getEndStrategy() {
            return event.get(DEFAULT_AUTH_FAILURE_HANDLER_END_STRATEGY, END);
        }
    }

}
