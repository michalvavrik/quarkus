package io.quarkus.oidc.runtime;

import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.CreationException;
import jakarta.enterprise.util.TypeLiteral;

import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.arc.InjectableInstance;
import io.quarkus.arc.SyntheticCreationalContext;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.oidc.DPoPNonceProvider;
import io.quarkus.oidc.Oidc;
import io.quarkus.oidc.TenantIdentityProvider;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.runtime.annotations.RuntimeInit;
import io.quarkus.runtime.annotations.StaticInit;
import io.quarkus.security.runtime.SecurityConfig;
import io.quarkus.security.spi.runtime.BlockingSecurityExecutor;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class OidcRecorder {
    public static final String ACR_VALUES_TO_MAX_AGE_SEPARATOR = "@#$%@";

    static final Logger LOG = Logger.getLogger(OidcRecorder.class);

    private final RuntimeValue<OidcConfig> oidcConfig;
    private final RuntimeValue<SecurityConfig> securityConfig;

    public OidcRecorder(final RuntimeValue<OidcConfig> oidcConfig, final RuntimeValue<SecurityConfig> securityConfig) {
        this.oidcConfig = oidcConfig;
        this.securityConfig = securityConfig;
    }

    public Supplier<DefaultTokenIntrospectionUserInfoCache> setupTokenCache(Supplier<Vertx> vertx) {
        return new Supplier<DefaultTokenIntrospectionUserInfoCache>() {
            @Override
            public DefaultTokenIntrospectionUserInfoCache get() {
                return new DefaultTokenIntrospectionUserInfoCache(oidcConfig.getValue(), vertx.get());
            }
        };
    }

    @StaticInit
    public void setUserInfoInjectionPointDetected(boolean userInfoInjectionPointDetected) {
        TenantContextFactory.userInfoInjectionPointDetected = userInfoInjectionPointDetected;
    }

    @RuntimeInit
    public Function<SyntheticCreationalContext<TenantConfigBean>, TenantConfigBean> createTenantConfigBean(
            Supplier<Vertx> vertx, Supplier<TlsConfigurationRegistry> registry,
            Supplier<ProxyConfigurationRegistry> proxyConfigurationRegistrySupplier,
            Set<OidcRoute> allowedRoutes, boolean stepUpAuthenticationPolicyEnabled) {
        return new Function<SyntheticCreationalContext<TenantConfigBean>, TenantConfigBean>() {
            @Override
            public TenantConfigBean apply(SyntheticCreationalContext<TenantConfigBean> ctx) {
                final OidcImpl oidc = new OidcImpl(oidcConfig.getValue());
                ctx.getInjectedReference(new TypeLiteral<Event<Oidc>>() {
                }).fire(oidc);
                return new TenantConfigBean(vertx.get(), registry.get(), oidc, securityConfig.getValue().events().enabled(),
                        proxyConfigurationRegistrySupplier.get(), allowedRoutes, stepUpAuthenticationPolicyEnabled);
            }
        };
    }

    public void initTenantConfigBean() {
        try {
            // makes sure that config of static tenants is validated during app startup and create static tenant contexts
            Arc.container().instance(TenantConfigBean.class).get();
        } catch (CreationException wrapper) {
            if (wrapper.getCause() instanceof RuntimeException runtimeException) {
                // so that users see ConfigurationException etc. without noise
                throw runtimeException;
            }
            throw wrapper;
        }
    }

    public Function<SyntheticCreationalContext<TenantIdentityProvider>, TenantIdentityProvider> createTenantIdentityProvider(
            String tenantName) {
        return new Function<SyntheticCreationalContext<TenantIdentityProvider>, TenantIdentityProvider>() {
            @Override
            public TenantIdentityProvider apply(SyntheticCreationalContext<TenantIdentityProvider> ctx) {
                DefaultTenantConfigResolver resolver = ctx.getInjectedReference(DefaultTenantConfigResolver.class);
                BlockingSecurityExecutor blockingExecutor = ctx.getInjectedReference(BlockingSecurityExecutor.class);
                InjectableInstance<DPoPNonceProvider> dPoPNonceProvider = ctx.getInjectedReference(new TypeLiteral<>() {
                });
                return new TenantSpecificOidcIdentityProvider(tenantName, resolver, blockingExecutor, dPoPNonceProvider);
            }
        };
    }

    public Handler<RoutingContext> getBackChannelLogoutHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(BackChannelLogoutHandler.class);
    }

    public Handler<RoutingContext> getResourceMetadataHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(ResourceMetadataHandler.class);
    }

    public Handler<RoutingContext> getClientIdMetadataHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(ClientIdMetadataHandler.class);
    }

    public Handler<RoutingContext> getAttestationJwksHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(AttestationJwksHandler.class);
    }
}
