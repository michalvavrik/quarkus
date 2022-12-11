package io.quarkus.oidc.client.filter.runtime;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

import io.quarkus.oidc.client.runtime.AbstractTokensProducer;
import io.quarkus.runtime.annotations.Recorder;

@Recorder
public class OidcClientFilterRecorder {

    private static volatile Map<String, String> clientInvokerToName = Map.of();

    public void setClientInvokerToName(Map<String, String> clientInvokerToName) {
        OidcClientFilterRecorder.clientInvokerToName = Map.copyOf(clientInvokerToName);
    }

    public static Map<String, String> getClientInvokerToName() {
        return clientInvokerToName;
    }

    public Supplier<AbstractTokensProducer> createTokensProducer(String clientId) {
        final Optional<String> clientIdOpt = Optional.ofNullable(clientId);
        return new Supplier<AbstractTokensProducer>() {
            @Override
            public AbstractTokensProducer get() {
                final var tokensProducer = new AbstractTokensProducer() {
                    @Override
                    protected Optional<String> clientId() {
                        return clientIdOpt;
                    }
                };
                tokensProducer.init();
                return tokensProducer;
            }
        };
    }

    public static String toTokensProducerBeanName(String clientId) {
        // beans created with OidcClientFilterRecorder#createTokensProducer are going to have this name
        return AbstractTokensProducer.class.getName() + "$$" + Objects.requireNonNull(clientId);
    }

}
