package io.quarkus.elytron.security.runtime;

import java.security.Permission;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.inject.spi.CDI;

import org.jboss.logging.Logger;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.PermissionMappable;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;

import io.quarkus.arc.runtime.BeanContainer;

/**
 * Runtime helpers used by the Elytron security services to assemble the {@linkplain SecurityDomain} and to hand it
 * over to the identity providers.
 */
public class ElytronRecorder {
    static final Logger log = Logger.getLogger(ElytronRecorder.class);

    public static void setDomainForIdentityProvider(BeanContainer bc, SecurityDomain domain) {
        bc.beanInstance(ElytronSecurityDomainManager.class).setDomain(domain);
    }

    /**
     * Build the {@linkplain SecurityDomain} from the realm services, adding the realms in the given order. The first
     * realm becomes the default realm of the domain and a realm added later replaces an earlier realm with the same
     * realm name.
     *
     * @param serviceNames the names of the realm services, in the order the realms are added to the domain
     * @param realmNames the realm names, parallel to {@code serviceNames}
     * @param securityRealms the realm services by service name
     * @return the security domain, or an empty optional when no realm is configured
     * @throws Exception on any error
     */
    public static Optional<SecurityDomain> buildDomain(List<String> serviceNames, List<String> realmNames,
            Map<String, SecurityRealm> securityRealms) throws Exception {
        SecurityDomain.Builder builder = null;
        for (int i = 0; i < serviceNames.size(); i++) {
            SecurityRealm realm = securityRealms.get(serviceNames.get(i));
            if (builder == null) {
                builder = configureDomainBuilder(realmNames.get(i), realm);
            } else {
                addRealm(builder, realmNames.get(i), realm);
            }
        }
        return builder == null ? Optional.empty() : Optional.of(builder.build());
    }

    /**
     * Create a {@linkplain SecurityDomain.Builder} for the given default {@linkplain SecurityRealm}.
     *
     * @param realmName - the default realm name
     * @param realm - the default SecurityRealm
     * @return the SecurityDomain.Builder
     * @throws Exception on any error
     */
    public static SecurityDomain.Builder configureDomainBuilder(String realmName, SecurityRealm realm)
            throws Exception {
        log.debugf("buildDomain, realm=%s", realm);

        SecurityDomain.Builder domain = SecurityDomain.builder()

                .addRealm(realmName, realm)

                .setRoleDecoder(new RoleDecoder() {
                    @Override
                    public Roles decodeRoles(AuthorizationIdentity authorizationIdentity) {
                        return CDI.current().select(DefaultRoleDecoder.class).get().decodeRoles(authorizationIdentity);
                    }
                })
                .build()
                .setDefaultRealmName(realmName)
                .setPermissionMapper(new PermissionMapper() {
                    @Override
                    public PermissionVerifier mapPermissions(PermissionMappable permissionMappable, Roles roles) {
                        return new PermissionVerifier() {
                            @Override
                            public boolean implies(Permission permission) {
                                return true;
                            }
                        };
                    }
                });
        if (CDI.current().select(RealmMapper.class).isResolvable()) {
            domain.setRealmMapper(CDI.current().select(RealmMapper.class).get());
        }

        return domain;
    }

    /**
     * Called to add a realm to the {@linkplain SecurityDomain} being built
     *
     * @param builder - SecurityDomain.Builder
     * @param realmName - the name of the SecurityRealm
     * @param realm - the SecurityRealm
     */
    public static void addRealm(SecurityDomain.Builder builder, String realmName, SecurityRealm realm) {
        builder.addRealm(realmName, realm).setRoleDecoder(new RoleDecoder() {
            @Override
            public Roles decodeRoles(AuthorizationIdentity authorizationIdentity) {
                return CDI.current().select(DefaultRoleDecoder.class).get().decodeRoles(authorizationIdentity);
            }
        }).build();
    }

}
