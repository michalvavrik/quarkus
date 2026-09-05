package io.quarkus.signals.deployment.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

import jakarta.enterprise.context.control.ActivateRequestContext;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.Authenticated;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.signals.Receives;
import io.quarkus.signals.Signal;
import io.quarkus.test.QuarkusExtensionTest;

public class SecurityIntegrationTest extends AbstractSignalTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(root -> root.addClasses(
                    AuthenticatedCmd.class, MyReceivers.class));

    @Inject
    Signal<AuthenticatedCmd> signal;

    @Inject
    CurrentIdentityAssociation identityAssociation;

    @ActivateRequestContext
    @Test
    public void testAuthenticationRequired() {
        MyReceivers.AUTHENTICATED_CMDS.clear();

        Stream.of("admin", "user").map(SecurityIntegrationTest::createSecurityIdentity).forEach(authenticatedUser -> {
            identityAssociation.setIdentity(authenticatedUser);
            String result = signal.reactive().request(new AuthenticatedCmd("Hello"), String.class)
                    .ifNoItem().after(defaultTimeout()).fail()
                    .await().indefinitely();
            assertEquals("hello " + authenticatedUser.getPrincipal().getName(), result);
        });

        assertThrows(UnauthorizedException.class, () -> {
            identityAssociation.setIdentity(createSecurityIdentity(""));
            signal.reactive().request(new AuthenticatedCmd("Hi"), String.class)
                    .ifNoItem().after(defaultTimeout()).fail()
                    .await().indefinitely();
        });

        assertEquals(2, MyReceivers.AUTHENTICATED_CMDS.size());
        assertTrue(MyReceivers.AUTHENTICATED_CMDS.stream().map(AuthenticatedCmd::value).allMatch(v -> v.startsWith("Hello")));
    }

    private static SecurityIdentity createSecurityIdentity(String name) {
        return QuarkusSecurityIdentity.builder()
                .setAnonymous(name.isEmpty())
                .setPrincipal(new QuarkusPrincipal(name))
                .addRole(name)
                .build();
    }

    // --- Signal types ---

    record AuthenticatedCmd(String value) {
    }

    // --- Receivers ---

    @Authenticated
    @Singleton
    public static class MyReceivers {

        static final List<AuthenticatedCmd> AUTHENTICATED_CMDS = new CopyOnWriteArrayList<>();

        @Inject
        SecurityIdentity securityIdentity;

        String process(@Receives AuthenticatedCmd cmd) {
            AUTHENTICATED_CMDS.add(cmd);
            return cmd.value().toLowerCase() + " " + securityIdentity.getPrincipal().getName();
        }

    }

}
