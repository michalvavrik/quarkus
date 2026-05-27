package io.quarkus.vertx.http.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import org.jboss.logging.Logger;

import io.quarkus.tls.CertificateUpdatedEvent;
import io.quarkus.tls.TlsConfiguration;
import io.vertx.core.http.HttpServer;

/**
 * A listener that listens for certificate updates and updates the HTTP server accordingly.
 */
@Singleton
public class HttpCertificateUpdateEventListener {

    private final static Logger LOG = Logger.getLogger(HttpCertificateUpdateEventListener.class);
    private final Map<String, List<CertificateUpdateRegistration>> registrations = new ConcurrentHashMap<>();

    private interface CertificateUpdateRegistration {

        void notify(CertificateUpdatedEvent event, CountDownLatch latch);

    }

    void register(Consumer<TlsConfiguration> tlsConfigurationConsumer, String tlsConfigurationName) {
        addRegistration(tlsConfigurationName, (event, latch) -> {
            tlsConfigurationConsumer.accept(event.tlsConfiguration());
            latch.countDown();
        });
    }

    public void register(HttpServer server, String tlsConfigurationName, String id) {
        addRegistration(tlsConfigurationName, (event, latch) -> {
            server.updateSSLOptions(event.tlsConfiguration().getSSLOptions())
                    .toCompletionStage().whenComplete(new BiConsumer<Boolean, Throwable>() {
                        @Override
                        public void accept(Boolean v, Throwable t) {
                            if (t == null) {
                                LOG.infof("The TLS configuration `%s` used by the HTTP server `%s` has been updated",
                                        event.name(), id);
                            } else {
                                LOG.warnf(t, "Failed to update TLS configuration `%s` for the HTTP server `%s`",
                                        event.name(), id);
                            }
                            latch.countDown();
                        }
                    });
        });
    }

    public void onCertificateUpdate(@Observes CertificateUpdatedEvent event) throws InterruptedException {
        var eventRegistrations = registrations.get(event.name());
        if (!eventRegistrations.isEmpty()) {
            CountDownLatch latch = new CountDownLatch(eventRegistrations.size());
            for (CertificateUpdateRegistration registration : eventRegistrations) {
                registration.notify(event, latch);
            }
            latch.await();
        }
    }

    private void addRegistration(String tlsConfigName, CertificateUpdateRegistration registration) {
        registrations.computeIfAbsent(tlsConfigName, k -> new ArrayList<>()).add(registration);
    }
}
