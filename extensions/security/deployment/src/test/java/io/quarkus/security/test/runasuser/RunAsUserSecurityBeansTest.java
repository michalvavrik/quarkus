package io.quarkus.security.test.runasuser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Principal;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.control.ActivateRequestContext;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.RunAsUser;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;

@ActivateRequestContext
class RunAsUserSecurityBeansTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar.addClass(WhoAmIBean.class));

    @ApplicationScoped
    static class WhoAmIBean {

        @Inject
        Principal principal;

        @Inject
        SecurityIdentity securityIdentity;

        @RunAsUser(user = "Mirek")
        public String getPrincipalName() {
            return principal.getName();
        }

        @RunAsUser(user = "Marek")
        public SecurityIdentity getSecurityIdentity() {
            return securityIdentity;
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
    }

}
