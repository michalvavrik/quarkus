package io.quarkus.hibernate.orm.rest.data.panache.deployment.security;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.builder.Version;
import io.quarkus.hibernate.orm.panache.PanacheEntity;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;

abstract class AbstractSecurityAnnotationTest {

    @RegisterExtension
    static final QuarkusUnitTest TEST = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addAsResource(new StringAsset(
                            """
                                            insert into item(id, name) values (1, 'first');
                                            insert into item(id, name) values (2, 'second');
                                            insert into piece(id, name) values (1, 'first');
                                            insert into piece(id, name) values (2, 'second');
                                    """),
                            "import.sql"))
            .setForcedDependencies(List.of(
                    Dependency.of("io.quarkus", "quarkus-jdbc-h2-deployment", Version.getVersion()),
                    Dependency.of("io.quarkus", "quarkus-rest-jackson-deployment", Version.getVersion()),
                    Dependency.of("io.quarkus", "quarkus-elytron-security-properties-file-deployment", Version.getVersion())))
            .overrideConfigKey("quarkus.datasource.db-kind", "h2")
            .overrideConfigKey("quarkus.security.users.embedded.enabled", "true")
            .overrideConfigKey("quarkus.security.users.embedded.plain-text", "true")
            .overrideConfigKey("quarkus.security.users.embedded.users.foo", "foo")
            .overrideConfigKey("quarkus.security.users.embedded.roles.foo", "user")
            .overrideConfigKey("quarkus.security.users.embedded.users.bar", "bar")
            .overrideConfigKey("quarkus.security.users.embedded.roles.bar", "admin")
            .overrideRuntimeConfigKey("quarkus.datasource.jdbc.url", "jdbc:h2:mem:test")
            .overrideRuntimeConfigKey("quarkus.hibernate-orm.schema-management.strategy", "drop-and-create");

    @Entity
    @Table(name = "item")
    public static class Item extends PanacheEntity {

        public String name;
    }

    @Entity
    @Table(name = "piece")
    public static class Piece extends PanacheEntity {

        public String name;
    }

    @ApplicationScoped
    public static class PermissionsAugmentor implements SecurityIdentityAugmentor {

        @Override
        public Uni<SecurityIdentity> augment(SecurityIdentity securityIdentity,
                AuthenticationRequestContext authenticationRequestContext) {
            if (securityIdentity != null && !securityIdentity.isAnonymous()) {
                if (securityIdentity.hasRole("admin")) {
                    return Uni.createFrom().item(QuarkusSecurityIdentity
                            .builder(securityIdentity)
                            .addPermissionAsString("count-1")
                            .addPermissionAsString("count-2")
                            .build());
                }
                if (securityIdentity.hasRole("user")) {
                    return Uni.createFrom().item(QuarkusSecurityIdentity
                            .builder(securityIdentity)
                            .addPermissionAsString("delete")
                            .addPermissionAsString("count-1")
                            .build());
                }
            }
            return Uni.createFrom().item(securityIdentity);
        }
    }
}
