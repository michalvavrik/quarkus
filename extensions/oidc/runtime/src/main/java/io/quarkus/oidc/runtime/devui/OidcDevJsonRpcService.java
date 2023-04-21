package io.quarkus.oidc.runtime.devui;

import io.smallrye.common.annotation.NonBlocking;

public class OidcDevJsonRpcService {

    static final OidcDevUiInfo DEV_UI_INFO_INSTANCE = new OidcDevUiInfo();

    @NonBlocking
    String getCardLabel() {
        return DEV_UI_INFO_INSTANCE.getCardLabel();
    }

}
