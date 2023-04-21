package io.quarkus.oidc.runtime.devui;

import io.quarkus.oidc.runtime.OidcConfigPropertySupplier;
import io.quarkus.runtime.annotations.Recorder;

import static io.quarkus.oidc.runtime.devui.OidcDevJsonRpcService.DEV_UI_INFO_INSTANCE;

@Recorder
public class OidcDevUiRecorder {

    public void setCardLabel(String oidcProviderName, String authorizationUrl, String authorizationPathConfigKey) {
        DEV_UI_INFO_INSTANCE.setCardLabel(
                new OidcDevUiInfo.CardLabel(
                        new OidcConfigPropertySupplier(authorizationPathConfigKey, authorizationUrl, true),
                        oidcProviderName)
        );
    }
}
