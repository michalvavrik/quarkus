package io.quarkus.email.authentication.deployment.test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import io.quarkus.email.authentication.EmailAuthenticationEvent;

@ApplicationScoped
public class TestSecurityEventObserver {

    private final List<EmailAuthenticationEvent> events = new CopyOnWriteArrayList<>();

    void observeEvent(@Observes EmailAuthenticationEvent event) {
        events.add(event);
    }

    List<EmailAuthenticationEvent> getEvents() {
        return List.copyOf(events);
    }

    void clear() {
        events.clear();
    }

}
