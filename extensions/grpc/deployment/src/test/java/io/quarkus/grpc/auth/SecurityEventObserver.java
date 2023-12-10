package io.quarkus.grpc.auth;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import io.quarkus.security.spi.runtime.SecurityEvent;

@Singleton
public class SecurityEventObserver {

    private final List<SecurityEvent> storage = new CopyOnWriteArrayList<>();

    void observe(@Observes SecurityEvent event) {
        storage.add(event);
    }

    List<SecurityEvent> getStorage() {
        return storage;
    }
}
