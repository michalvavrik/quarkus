package io.quarkus.vertx.http.runtime.security;

import io.quarkus.vertx.http.security.form.token.FormAuthenticationTokenStorage;
import io.smallrye.mutiny.Uni;

final class CookieFormAuthenticationTokenStorage implements FormAuthenticationTokenStorage {

    @Override
    public Uni<Void> storeToken(char[] token, String principalName) {
        return null;
    }

    @Override
    public Uni<String> findPrincipalNameByToken(char[] token) {
        return null;
    }
}
