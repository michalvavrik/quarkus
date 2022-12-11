package io.quarkus.oidc.client.reactive.filter.runtime;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.resteasy.reactive.client.impl.ClientImpl;
import org.jboss.resteasy.reactive.client.spi.ResteasyReactiveClientRequestContext;

import io.quarkus.arc.All;
import io.quarkus.oidc.client.Tokens;
import io.quarkus.oidc.client.runtime.AbstractTokensProducer;
import io.smallrye.mutiny.Uni;

public abstract class TokensProducerRegistry {

    /**
     * True if at least one @OidcClientFilter annotation instance specified non-default OidcClient name.
     */
    static boolean searchForNonDefaultProducers = false;

    public static final String DEFAULT_TOKENS_PRODUCER = "io.quarkus.oidc.client.reactive.filter.runtime.defaultTokenProducer";

    @All
    @Inject
    List<TokensProducer> tokensProducerList;

    @Named(DEFAULT_TOKENS_PRODUCER)
    @Inject
    TokensProducer defaultTokensProducer;

    protected Uni<Tokens> getTokens(ResteasyReactiveClientRequestContext requestContext) {
        return findProducer(requestContext).getTokens();
    }

    private AbstractTokensProducer findProducer(ResteasyReactiveClientRequestContext requestContext) {

        if (searchForNonDefaultProducers) {
            // find tokens producer that uses OidcClient with name specified via @OidcClientFilter("someClientName")
            final String clientInvokerClass = ((ClientImpl) requestContext.getClient()).getClientInvokerClass();
            if (clientInvokerClass != null) {
                for (TokensProducer tokensProducer : tokensProducerList) {
                    if (clientInvokerClass.equals(tokensProducer.clientInvokerClass())) {
                        return tokensProducer;
                    }
                }
            }
        }

        return defaultTokensProducer;
    }

}
