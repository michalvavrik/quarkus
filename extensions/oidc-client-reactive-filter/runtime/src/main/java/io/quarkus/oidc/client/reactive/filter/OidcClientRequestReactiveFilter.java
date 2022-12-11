package io.quarkus.oidc.client.reactive.filter;

import java.util.function.Consumer;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.client.spi.ResteasyReactiveClientRequestContext;
import org.jboss.resteasy.reactive.client.spi.ResteasyReactiveClientRequestFilter;

import io.quarkus.oidc.client.Tokens;
import io.quarkus.oidc.client.reactive.filter.runtime.TokensProducerRegistry;
import io.quarkus.oidc.client.runtime.DisabledOidcClientException;
import io.quarkus.oidc.common.runtime.OidcConstants;

@Priority(Priorities.AUTHENTICATION)
public class OidcClientRequestReactiveFilter extends TokensProducerRegistry implements ResteasyReactiveClientRequestFilter {
    private static final Logger LOG = Logger.getLogger(OidcClientRequestReactiveFilter.class);
    private static final String BEARER_SCHEME_WITH_SPACE = OidcConstants.BEARER_SCHEME + " ";

    @Override
    public void filter(ResteasyReactiveClientRequestContext requestContext) {
        requestContext.suspend();

        getTokens(requestContext).subscribe().with(new Consumer<>() {
            @Override
            public void accept(Tokens tokens) {
                requestContext.getHeaders().putSingle(HttpHeaders.AUTHORIZATION,
                        BEARER_SCHEME_WITH_SPACE + tokens.getAccessToken());
                requestContext.resume();
            }
        }, new Consumer<>() {
            @Override
            public void accept(Throwable t) {
                if (t instanceof DisabledOidcClientException) {
                    LOG.debug("Client is disabled");
                    requestContext.abortWith(Response.status(Response.Status.INTERNAL_SERVER_ERROR).build());
                } else {
                    LOG.debugf("Access token is not available, aborting the request with HTTP 401 error: %s", t.getMessage());
                    requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
                }
                requestContext.resume();
            }
        });
    }

}
