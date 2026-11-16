package io.quarkus.oidc.runtime;

import static io.quarkus.oidc.runtime.OidcRecorder.LOG;

import java.util.function.Consumer;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.security.AuthenticationFailedException;
import io.vertx.ext.web.RoutingContext;

/**
 * Interceptor that selects the OIDC tenant based on the {@link io.quarkus.oidc.Tenant} annotation.
 *
 * @param tenantId tenant selected with the annotation
 */
public record TenantResolverInterceptor(String tenantId) implements Consumer<RoutingContext> {

    @Override
    public void accept(RoutingContext routingContext) {
        OidcTenantConfig tenantConfig = routingContext.get(OidcTenantConfig.class.getName());
        if (tenantConfig != null) {
            // authentication has happened before @Tenant annotation was matched with the HTTP request
            String tenantUsedForAuth = tenantConfig.tenantId().orElse(null);
            if (tenantId.equals(tenantUsedForAuth)) {
                // @Tenant selects the same tenant as already selected
                return;
            } else {
                // @Tenant selects the different tenant than already selected
                throw new AuthenticationFailedException(
                        """
                                The '%1$s' selected with the @Tenant annotation must be used to authenticate
                                the request but it was already authenticated with the '%2$s' tenant. It
                                can happen if the '%1$s' is selected with an annotation but '%2$s' is
                                resolved during authentication required by the HTTP Security Policy which
                                is enforced before the JAX-RS chain is run. In such cases, please set the
                                'quarkus.http.auth.permission."permissions".applies-to=JAXRS' to all HTTP
                                Security Policies which secure the same REST endpoints as the ones
                                where the '%1$s' tenant is resolved by the '@Tenant' annotation.
                                """
                                .formatted(tenantId, tenantUsedForAuth));
            }
        }

        LOG.debugf("@Tenant annotation set a '%s' tenant id on the %s request path", tenantId,
                routingContext.request().path());
        routingContext.put(OidcUtils.TENANT_ID_SET_BY_ANNOTATION, tenantId);
        routingContext.put(OidcUtils.TENANT_ID_ATTRIBUTE, tenantId);
    }

}
