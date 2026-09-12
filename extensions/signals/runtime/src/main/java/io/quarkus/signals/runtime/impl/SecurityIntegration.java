package io.quarkus.signals.runtime.impl;

import static io.quarkus.signals.spi.ReceiverInterceptor.ID_REQUEST_CONTEXT;
import static io.quarkus.signals.spi.ReceiverInterceptor.ID_SECURITY_IDENTITY;

import jakarta.inject.Singleton;

import io.quarkus.arc.Arc;
import io.quarkus.arc.ClientProxy;
import io.quarkus.arc.ManagedContext;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.AbstractSecurityIdentityAssociation;
import io.quarkus.signals.spi.ReceiverInterceptor;
import io.quarkus.signals.spi.RelativeOrder;
import io.quarkus.signals.spi.SignalMetadataEnricher;
import io.smallrye.common.annotation.Identifier;
import io.smallrye.mutiny.Uni;

@Identifier(ID_SECURITY_IDENTITY)
@RelativeOrder(after = ID_REQUEST_CONTEXT)
@Singleton
public final class SecurityIntegration implements SignalMetadataEnricher, ReceiverInterceptor {

    private static final String SECURITY_IDENTITY_KEY = "io.quarkus.signals.runtime.impl#security_identity";

    private final CurrentIdentityAssociation currentIdentity;
    private final ManagedContext requestContext;

    SecurityIntegration(CurrentIdentityAssociation currentIdentity) {
        this.currentIdentity = currentIdentity;
        this.requestContext = Arc.requireContainer().requestContext();
    }

    @Override
    public void enrich(EnrichmentContext context) {
        // all builtin identity associations are request scoped, therefore we cannot get SecurityIdentity from CDI
        if (requestContext.isActive()
                && ClientProxy.unwrap(currentIdentity) instanceof AbstractSecurityIdentityAssociation abstractAssociation) {
            SecurityIdentity securityIdentity = abstractAssociation.getIdentityOrNull();
            if (securityIdentity != null) {
                context.putMetadata(SECURITY_IDENTITY_KEY, securityIdentity);
            }
        }
    }

    @Override
    public Uni<Object> intercept(InterceptionContext context) {
        if (requestContext.isActive()
                && context.signalContext().metadata().get(SECURITY_IDENTITY_KEY) instanceof SecurityIdentity securityIdentity) {
            currentIdentity.setIdentity(securityIdentity);
        }
        return context.proceed();
    }
}
