package io.quarkus.oidc.client.reactive.filter.runtime;

import java.util.Optional;
import java.util.function.Supplier;

import io.quarkus.oidc.client.runtime.OidcClientsConfig;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.runtime.configuration.ConfigurationException;

@Recorder
public class OidcClientReactiveFilterRecorder {

    private final RuntimeValue<OidcClientsConfig> oidcClientsConfigRuntimeValue;

    public OidcClientReactiveFilterRecorder(RuntimeValue<OidcClientsConfig> oidcClientsConfigRuntimeValue) {
        this.oidcClientsConfigRuntimeValue = oidcClientsConfigRuntimeValue;
    }

    public Supplier<TokensProducer> createTokensProducer(String clientName, String clientInvokerClass) {
        final Optional<String> clientId = Optional.ofNullable(clientName);
        final boolean earlyTokensAcquisition;
        if (clientName == null) {
            earlyTokensAcquisition = oidcClientsConfigRuntimeValue.getValue().defaultClient.earlyTokensAcquisition;
        } else {
            if (oidcClientsConfigRuntimeValue.getValue().namedClients != null
                    && oidcClientsConfigRuntimeValue.getValue().namedClients.get(clientName) != null) {
                earlyTokensAcquisition = oidcClientsConfigRuntimeValue.getValue().namedClients
                        .get(clientName).earlyTokensAcquisition;
            } else {
                throw new ConfigurationException(
                        String.format("Unknown OIDC client '%s' specified via @OidcClientFilter", clientName));
            }
        }

        return new Supplier<>() {
            @Override
            public TokensProducer get() {
                return new TokensProducer(earlyTokensAcquisition) {

                    @Override
                    protected Optional<String> clientId() {
                        return clientId;
                    }

                    @Override
                    String clientInvokerClass() {
                        return clientInvokerClass;
                    }
                };
            }
        };
    }

    public void searchForNonDefaultProducers() {
        TokensProducerRegistry.searchForNonDefaultProducers = true;
    }

}
