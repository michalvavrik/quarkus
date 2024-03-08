package io.quarkus.security.test.rolesallowed;

import io.quarkus.security.test.utils.AuthData;
import io.quarkus.security.test.utils.IdentityMock;
import io.quarkus.security.test.utils.SecurityTestUtils;
import io.quarkus.test.QuarkusUnitTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class SecurityIdentityConfigurationBasedRolesMappingTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(RolesAllowedMappingBean.class, IdentityMock.class, AuthData.class, SecurityTestUtils.class)
                    .addAsResource(new StringAsset("""
                            roles-list=admin,user
                            quarkus.security.roles.root=admin,user
                            quarkus.security.roles.role1=role2
                            quarkus.security.roles.role3=role1,role4
                            """), "application.properties"));

    @Inject
    RolesAllowedMappingBean bean;

    @Test
    public void testNewRolesAdded() {

    }

    @Test
    public void testOldRolesNotRemoved() {

    }

    @Test
    public void testIdentityWithoutMappedRolesNotAugmented() {

    }

    @Test
    public void testRolesAllowedExpressionWorks() {

    }

    @Singleton
    public static class RolesAllowedMappingBean {

    }

}
