package io.quarkus.oidc.runtime.devui;

import java.util.Objects;
import java.util.function.Supplier;

final class OidcDevUiInfo {

    private CardLabel cardLabel;

    void setCardLabel(CardLabel cardLabel) {
        this.cardLabel = Objects.requireNonNull(cardLabel);
    }

    String getCardLabel() {
        if (cardLabel != null) {
            if (cardLabel.oidcProviderName != null) {
                // e.g. 'Keycloak provider'
                return cardLabel.oidcProviderName + "provider";
            } else if (cardLabel.authorizationUrl.get() != null) {
                return "Dev Console";
            }
        }

        return "";
    }

    static final class CardLabel {
        private final Supplier<String> authorizationUrl;
        private final String oidcProviderName;

        CardLabel(Supplier<String> authorizationUrl, String oidcProviderName) {
            this.authorizationUrl = authorizationUrl;
            this.oidcProviderName = oidcProviderName;
        }
    }
}
