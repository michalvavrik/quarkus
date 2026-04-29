package io.quarkus.hibernate.panache.deployment.test.security;

import java.security.Permission;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.security.credential.Credential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.smallrye.mutiny.Uni;

@ApplicationScoped
class TestSecurityIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

    private volatile SecurityIdentity identity;

    @Override
    public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
        return UsernamePasswordAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
            AuthenticationRequestContext context) {
        return Uni.createFrom().item(identity);
    }

    void clear() {
        identity = null;
    }

    void setIdentity(String roleName) {
        identity = new SecurityIdentity() {
            @Override
            public Principal getPrincipal() {
                return new Principal() {
                    @Override
                    public String getName() {
                        return roleName;
                    }
                };
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }

            @Override
            public Set<String> getRoles() {
                return Set.of(roleName);
            }

            @Override
            public boolean hasRole(String role) {
                return getRoles().contains(role);
            }

            @Override
            public Set<Permission> getPermissions() {
                return Set.of();
            }

            @Override
            public <T extends Credential> T getCredential(Class<T> credentialType) {
                return null;
            }

            @Override
            public Set<Credential> getCredentials() {
                return Set.of();
            }

            @Override
            public <T> T getAttribute(String name) {
                return null;
            }

            @Override
            public Map<String, Object> getAttributes() {
                return Map.of();
            }

            @Override
            public Uni<Boolean> checkPermission(Permission permission) {
                return null;
            }
        };
    }
}
