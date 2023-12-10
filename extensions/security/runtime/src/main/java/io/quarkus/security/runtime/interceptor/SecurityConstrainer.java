package io.quarkus.security.runtime.interceptor;

import java.lang.reflect.Method;
import java.util.function.Consumer;
import java.util.function.Function;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkus.runtime.BlockingOperationNotAllowedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.SecurityConfig;
import io.quarkus.security.runtime.SecurityIdentityAssociation;
import io.quarkus.security.spi.runtime.AuthorizationFailureEvent;
import io.quarkus.security.spi.runtime.AuthorizationSuccessEvent;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.security.spi.runtime.SecurityCheckStorage;
import io.quarkus.security.spi.runtime.SecurityEventHelper;
import io.smallrye.mutiny.Uni;

/**
 * @author Michal Szynkiewicz, michal.l.szynkiewicz@gmail.com
 */
@Singleton
public class SecurityConstrainer {

    public static final Object CHECK_OK = new Object();
    private final SecurityCheckStorage storage;
    private final Event<AuthorizationFailureEvent> authZFailureEvent;
    private final Event<AuthorizationSuccessEvent> authZSuccessEvent;
    private final boolean isAuthZFailureObserved;
    private final boolean isAuthZSuccessObserved;

    @Inject
    SecurityIdentityAssociation identityAssociation;

    SecurityConstrainer(SecurityCheckStorage storage, BeanManager beanManager, SecurityConfig securityConfig,
            Event<AuthorizationFailureEvent> authZFailureEvent, Event<AuthorizationSuccessEvent> authZSuccessEvent) {
        this.storage = storage;
        var eventHelper = SecurityEventHelper.of(AuthorizationSuccessEvent.EMPTY_INSTANCE,
                AuthorizationFailureEvent.EMPTY_INSTANCE, beanManager, securityConfig.events().enabled());
        this.authZSuccessEvent = eventHelper.fireEventOnSuccess() ? authZSuccessEvent : null;
        this.authZFailureEvent = eventHelper.fireEventOnFailure() ? authZFailureEvent : null;
        this.isAuthZFailureObserved = eventHelper.fireEventOnFailure();
        this.isAuthZSuccessObserved = eventHelper.fireEventOnSuccess();
    }

    public void check(Method method, Object[] parameters) {
        SecurityCheck securityCheck = storage.getSecurityCheck(method);
        SecurityIdentity identity = null;
        if (securityCheck != null && !securityCheck.isPermitAll()) {
            try {
                identity = identityAssociation.getIdentity();
            } catch (BlockingOperationNotAllowedException blockingException) {
                throw new BlockingOperationNotAllowedException(
                        "Blocking security check attempted in code running on the event loop. " +
                                "Make the secured method return an async type, i.e. Uni, Multi or CompletionStage, or " +
                                "use an authentication mechanism that sets the SecurityIdentity in a blocking manner " +
                                "prior to delegating the call",
                        blockingException);
            }
            if (isAuthZFailureObserved) {
                try {
                    securityCheck.apply(identity, method, parameters);
                } catch (Exception exception) {
                    fireAuthZFailureEvent(identity, exception, securityCheck);
                    throw exception;
                }
            } else {
                securityCheck.apply(identity, method, parameters);
            }
        }
        if (isAuthZSuccessObserved) {
            fireAuthZSuccessEvent(securityCheck, identity);
        }
    }

    public Uni<?> nonBlockingCheck(Method method, Object[] parameters) {
        SecurityCheck securityCheck = storage.getSecurityCheck(method);
        if (securityCheck != null) {
            if (!securityCheck.isPermitAll()) {
                return identityAssociation.getDeferredIdentity()
                        .onItem()
                        .transformToUni(new Function<SecurityIdentity, Uni<?>>() {
                            @Override
                            public Uni<?> apply(SecurityIdentity securityIdentity) {
                                Uni<?> checkResult = securityCheck.nonBlockingApply(securityIdentity, method, parameters);
                                if (isAuthZFailureObserved) {
                                    checkResult = checkResult.onFailure().invoke(new Consumer<Throwable>() {
                                        @Override
                                        public void accept(Throwable throwable) {
                                            fireAuthZFailureEvent(securityIdentity, throwable, securityCheck);
                                        }
                                    });
                                }
                                if (isAuthZSuccessObserved) {
                                    checkResult = checkResult.invoke(new Runnable() {
                                        @Override
                                        public void run() {
                                            fireAuthZSuccessEvent(securityCheck, securityIdentity);
                                        }
                                    });
                                }
                                return checkResult;
                            }
                        });
            } else if (isAuthZSuccessObserved) {
                fireAuthZSuccessEvent(securityCheck, null);
            }
        }
        return Uni.createFrom().item(CHECK_OK);
    }

    private void fireAuthZSuccessEvent(SecurityCheck securityCheck, SecurityIdentity identity) {
        var securityCheckName = securityCheck == null ? null : securityCheck.getClass().getName();
        var event = new AuthorizationSuccessEvent(identity, securityCheckName, null);
        authZSuccessEvent.fire(event);
        authZSuccessEvent.fireAsync(event);
    }

    private void fireAuthZFailureEvent(SecurityIdentity identity, Throwable failure, SecurityCheck securityCheck) {
        var event = new AuthorizationFailureEvent(identity, failure, securityCheck.getClass().getName());
        authZFailureEvent.fire(event);
        authZFailureEvent.fireAsync(event);
    }
}
