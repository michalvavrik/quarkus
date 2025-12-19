package io.quarkus.security.test.runasuser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Principal;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.control.ActivateRequestContext;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.RunAsUser;
import io.quarkus.test.QuarkusUnitTest;

class RunAsUserSecurityBeansTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar.addClass(WhoAmIBean.class));

    @ActivateRequestContext
    @ApplicationScoped
    static class WhoAmIBean {

        @Inject
        Principal principal;

        @RunAsUser(user = "Mirek")
        public String getPrincipalName() {
            return principal.getName();
        }

    }

    @Inject
    WhoAmIBean whoAmIBean;

    @Test
    void testPrincipalName() {
        assertEquals("Mirek", whoAmIBean.getPrincipalName());
    }

}
