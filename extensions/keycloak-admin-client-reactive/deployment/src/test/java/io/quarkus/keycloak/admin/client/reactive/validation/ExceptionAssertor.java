package io.quarkus.keycloak.admin.client.reactive.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.Consumer;

import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientFactory;

class ExceptionAssertor implements Consumer<Throwable> {

    private final String requiredProperty;

    ExceptionAssertor(String requiredProperty) {
        this.requiredProperty = requiredProperty;
    }

    @Override
    public void accept(Throwable throwable) {
        Throwable e = throwable;
        Throwable match = null;
        while (e != null) {
            // 'instanceof' won't work here, exception is thrown in @Recorder
            if (e.getClass().getName().equals(KeycloakAdminClientFactory.KeycloakAdminClientException.class.getName())) {
                match = e;
                break;
            }
            e = e.getCause();
        }
        assertNotNull(match);
        final String msg = match.getMessage();
        assertTrue(msg.contains("requires"), msg);
        assertTrue(msg.contains(requiredProperty), msg);
    }
}
