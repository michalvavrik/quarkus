package io.quarkus.oidc.client.reactive.filter.runtime;

import org.jboss.logging.Logger;

import io.quarkus.oidc.client.runtime.AbstractTokensProducer;

public abstract class TokensProducer extends AbstractTokensProducer {

    private static final Logger LOG = Logger.getLogger(TokensProducer.class);

    TokensProducer(boolean earlyTokensAcquisition) {
        this.earlyTokenAcquisition = earlyTokensAcquisition;
        init();
    }

    abstract String clientInvokerClass();

    @Override
    protected void initTokens() {
        if (earlyTokenAcquisition) {
            LOG.debug("Token acquisition will be delayed until this filter is executed to avoid blocking an IO thread");
        }
    }
}
