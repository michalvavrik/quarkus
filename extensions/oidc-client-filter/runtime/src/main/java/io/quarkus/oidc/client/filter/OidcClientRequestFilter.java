package io.quarkus.oidc.client.filter;

import static io.quarkus.oidc.client.filter.runtime.OidcClientFilterRecorder.toTokensProducerBeanName;

import java.io.IOException;
import java.util.Optional;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.jboss.logging.Logger;
import org.jboss.resteasy.client.jaxrs.internal.ClientRequestContextImpl;

import io.quarkus.arc.Arc;
import io.quarkus.oidc.client.filter.runtime.OidcClientFilterConfig;
import io.quarkus.oidc.client.filter.runtime.OidcClientFilterRecorder;
import io.quarkus.oidc.client.runtime.AbstractTokensProducer;
import io.quarkus.oidc.client.runtime.DisabledOidcClientException;
import io.quarkus.oidc.common.runtime.OidcConstants;

@Provider
@Singleton
@Priority(Priorities.AUTHENTICATION)
public class OidcClientRequestFilter extends AbstractTokensProducer implements ClientRequestFilter {
    private static final Logger LOG = Logger.getLogger(OidcClientRequestFilter.class);
    private static final String BEARER_SCHEME_WITH_SPACE = OidcConstants.BEARER_SCHEME + " ";
    private final boolean searchForNamedOidcClients;
    @Inject
    OidcClientFilterConfig oidcClientFilterConfig;

    public OidcClientRequestFilter() {
        this.searchForNamedOidcClients = !OidcClientFilterRecorder.getClientInvokerToName().isEmpty();
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        try {
            final String accessToken = getAccessToken(requestContext);
            requestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, BEARER_SCHEME_WITH_SPACE + accessToken);
        } catch (DisabledOidcClientException ex) {
            requestContext.abortWith(Response.status(500).build());
        } catch (Exception ex) {
            LOG.debugf("Access token is not available, aborting the request with HTTP 401 error: %s", ex.getMessage());
            requestContext.abortWith(Response.status(401).build());
        }
    }

    private String getAccessToken(ClientRequestContext requestContext) {
        return getTokensProducer(requestContext).awaitTokens().getAccessToken();
    }

    private AbstractTokensProducer getTokensProducer(ClientRequestContext requestContext) {
        // check if we can link the request with named OidcClient
        if (searchForNamedOidcClients && requestContext instanceof ClientRequestContextImpl) {
            final var invocation = ((ClientRequestContextImpl) requestContext).getInvocation();
            if (invocation != null && invocation.getClientInvoker().getDeclaring() != null) {
                final String clientId = OidcClientFilterRecorder.getClientInvokerToName()
                        .get(invocation.getClientInvoker().getDeclaring().getName());
                if (clientId != null) {
                    // request have been invoked for a Rest client annotated with @OidcClient("clientName")
                    return Arc.container()
                            .<AbstractTokensProducer> instance(toTokensProducerBeanName(clientId))
                            .get();
                }
            }
        }
        return this;
    }

    protected Optional<String> clientId() {
        return oidcClientFilterConfig.clientName;
    }
}
