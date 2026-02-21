package io.quarkus.email.authentication.deployment.test;

import static io.quarkus.email.authentication.EmailAuthenticationTokenSender.EMAIL;

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

    private record UserDetail(String email, Set<String> roles) {
    }

    private static final Map<String, UserDetail> knownUsers = new ConcurrentHashMap<>();

    @Override
    public Class<TrustedAuthenticationRequest> getRequestType() {
        return TrustedAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest req, AuthenticationRequestContext reqCtx) {
        String principalName = req.getPrincipal();
        if (knownUsers.containsKey(principalName)) {
            var userDetail = knownUsers.get(principalName);
            return Uni.createFrom().item(
                    QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal(principalName))
                            .addRoles(userDetail.roles)
                            .addAttributes(userDetail.email == null ? Map.of() : Map.of(EMAIL, userDetail.email))
                            .setAnonymous(false)
                            .build());
        }
        return Uni.createFrom().nullItem();
    }

    static Builder reset() {
        knownUsers.clear();
        return new Builder();
    }

    static Builder addUser(String username, String email, String... roles) {
        return new Builder().addUser(username, email, roles);
    }

    static final class Builder {

        Builder addUser(String username) {
            return addUser(username, null);
        }

        Builder addUser(String username, String email, String... roles) {
            knownUsers.put(username, new UserDetail(email, Set.of(roles)));
            return this;
        }

    }
}
