package io.quarkus.vertx.http.security.form.token;

import java.util.Arrays;

import jakarta.inject.Singleton;

import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.security.token.FormAuthenticationTokenSender;
import io.smallrye.mutiny.Uni;

@Singleton
public final class InMemoryAuthTokenTestSender implements FormAuthenticationTokenSender {

    private volatile char[] token;

    @Override
    public Uni<Void> send(SecurityIdentity securityIdentity, PasswordCredential authenticationTokenCredential) {
        this.token = Arrays.copyOf(authenticationTokenCredential.getPassword(),
                authenticationTokenCredential.getPassword().length);
        return Uni.createFrom().voidItem();
    }

    char[] getToken() {
        return token;
    }

    void clean() {
        token = null;
    }
}
