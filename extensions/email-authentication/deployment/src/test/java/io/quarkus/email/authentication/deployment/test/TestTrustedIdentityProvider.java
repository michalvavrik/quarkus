package io.quarkus.email.authentication.deployment.test;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@ApplicationScoped
class TestTrustedIdentityProvider implements IdentityProvider<TrustedAuthenticationRequest> {

    private static final Map<String, Set<String>> knownUsers = new ConcurrentHashMap<>();

    @Override
    public Class<TrustedAuthenticationRequest> getRequestType() {
        return TrustedAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest req, AuthenticationRequestContext reqCtx) {
        String principalName = req.getPrincipal();
        if (knownUsers.containsKey(principalName)) {
            return Uni.createFrom().item(
                    QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal(principalName))
                            .addRoles(knownUsers.get(principalName))
                            .setAnonymous(false)
                            .build());
        }
        return Uni.createFrom().nullItem();
    }

    static Builder reset() {
        knownUsers.clear();
        return new Builder();
    }

    static final class Builder {

        Builder addUser(String username, String... roles) {
            knownUsers.put(username, Set.of(roles));
            return this;
        }

    }
}
