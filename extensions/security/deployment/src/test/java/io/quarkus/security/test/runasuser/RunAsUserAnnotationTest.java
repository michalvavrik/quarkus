package io.quarkus.security.test.runasuser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Principal;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.control.ActivateRequestContext;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.RunAsUser;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;

@ActivateRequestContext
class RunAsUserAnnotationTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
            .addClasses(WhoAmIBean.class));

    @ApplicationScoped
    static class WhoAmIBean {

        @Inject
        Principal principal;

        @Inject
        SecurityIdentity securityIdentity;

        @Inject
        CurrentIdentityAssociation currentIdentityAssociation;

        @RunAsUser(user = "Mirek")
        String getPrincipalName() {
            return principal.getName();
        }

        @RunAsUser(user = "Marek")
        SecurityIdentity getSecurityIdentity() {
            return securityIdentity;
        }

        @RunAsUser(user = "Milan", roles = { "user", "admin" })
        SecurityIdentity getIdentityWithRoles() {
            return securityIdentity;
        }

        @RunAsUser(user = "Michal")
        CurrentIdentityAssociation getCurrentIdentityAssociation() {
            return currentIdentityAssociation;
        }
    }

    @Inject
    WhoAmIBean whoAmIBean;

    @Test
    void testPrincipalName() {
        assertEquals("Mirek", whoAmIBean.getPrincipalName());
    }

    @Test
    void testSecurityIdentity() {
        var identity = whoAmIBean.getSecurityIdentity();
        assertEquals("Marek", identity.getPrincipal().getName());
        assertEquals(0, identity.getRoles().size());
    }

    @Test
    void testSecurityIdentityRoles() {
        var identity = whoAmIBean.getIdentityWithRoles();
        assertEquals("Milan", identity.getPrincipal().getName());
        assertEquals(2, identity.getRoles().size());
        assertTrue(identity.hasRole("user"));
        assertTrue(identity.hasRole("admin"));
    }

    @Test
    void testCurrentIdentityAssociation() {
        var association = whoAmIBean.getCurrentIdentityAssociation();
        var identity = association.getIdentity();
        String principalName = identity.getPrincipal().getName();
        assertEquals("Michal", principalName);
    }

}
