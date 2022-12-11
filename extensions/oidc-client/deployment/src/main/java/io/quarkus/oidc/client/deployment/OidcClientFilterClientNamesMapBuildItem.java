package io.quarkus.oidc.client.deployment;

import java.util.Map;

import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.oidc.client.filter.OidcClientFilter;

/**
 * Contains OIDC Client names specified via {@link OidcClientFilter#value()} linked to the target Rest client class.
 */
public final class OidcClientFilterClientNamesMapBuildItem extends SimpleBuildItem {

    private final Map<String, String> clientInvokerClassToName;

    OidcClientFilterClientNamesMapBuildItem(Map<String, String> clientInvokerClassToName) {
        this.clientInvokerClassToName = Map.copyOf(clientInvokerClassToName);
    }

    public Map<String, String> getClientInvokerClassToName() {
        return clientInvokerClassToName;
    }

}
