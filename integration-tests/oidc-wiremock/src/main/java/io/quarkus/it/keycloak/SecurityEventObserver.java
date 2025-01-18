package io.quarkus.it.keycloak;

import jakarta.enterprise.event.Observes;

import io.quarkus.security.spi.runtime.SecurityEvent;

public class SecurityEventObserver {

    void observe(@Observes SecurityEvent event) {
        var eventProps = event.getEventProperties();
        System.out.println("//////////////// event " + event.getClass().getName());
    }

}
