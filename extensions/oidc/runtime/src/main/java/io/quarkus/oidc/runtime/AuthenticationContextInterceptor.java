package io.quarkus.oidc.runtime;

import static io.quarkus.oidc.runtime.OidcRecorder.ACR_VALUES_TO_MAX_AGE_SEPARATOR;
import static io.quarkus.oidc.runtime.OidcRecorder.LOG;
import static io.quarkus.runtime.configuration.DurationConverter.parseDuration;

import java.time.Duration;
import java.util.function.Consumer;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.security.AuthenticationFailedException;
import io.vertx.ext.web.RoutingContext;

/**
 * Interceptor that requires the step-up authentication based
 * on the {@link io.quarkus.oidc.AuthenticationContext} annotation.
 *
 * @param acrValues required 'acr' values separated by a comma
 * @param maxAge maximum token age, or an empty string if there is none
 * @param policy step-up authentication policy applied on the request
 */
public record AuthenticationContextInterceptor(String acrValues, String maxAge,
        StepUpAuthenticationPolicy policy) implements Consumer<RoutingContext> {

    /**
     * @param annotationBinding required 'acr' values and maximum token age of the annotation instance
     * @return interceptor for the annotation instance
     */
    public static AuthenticationContextInterceptor of(String annotationBinding) {
        int separatorIndex = annotationBinding.indexOf(ACR_VALUES_TO_MAX_AGE_SEPARATOR);
        String acrValues = annotationBinding.substring(0, separatorIndex);
        String maxAgeAsStr = annotationBinding.substring(separatorIndex + ACR_VALUES_TO_MAX_AGE_SEPARATOR.length());
        final Duration maxAgeDuration;
        if (maxAgeAsStr.isEmpty()) {
            maxAgeDuration = null;
        } else {
            maxAgeDuration = parseDuration(maxAgeAsStr);
        }
        StepUpAuthenticationPolicy policy = new StepUpAuthenticationPolicy(acrValues, maxAgeDuration);
        return new AuthenticationContextInterceptor(acrValues, maxAgeAsStr, policy);
    }

    @Override
    public void accept(RoutingContext routingContext) {
        String requestPath = routingContext.request().path();
        OidcTenantConfig tenantConfig = routingContext.get(OidcTenantConfig.class.getName());
        if (tenantConfig != null || routingContext.user() != null) {
            throw new AuthenticationFailedException("""
                    Authentication has happened before the '@AuthenticationContext' annotation was
                    matched with the HTTP request path '%s'. It can happen when the authentication
                    is required by an HTTP Security Policy before the JAX-RS chain is run. In such
                    cases, please set the 'quarkus.http.auth.permission."permissions".applies-to=JAXRS'
                    to all HTTP Security Policies which secure the same REST endpoints as the ones
                    annotated with the '@AuthenticationContext' annotation.
                    """.formatted(requestPath));
        }
        LOG.debugf("The '@AuthenticationContext' annotation set required 'acr' values '%s' "
                + "and max age '%s' for the request path '%s'", acrValues, maxAge, requestPath);
        policy.storeSelfOnContext(routingContext);
    }

}
