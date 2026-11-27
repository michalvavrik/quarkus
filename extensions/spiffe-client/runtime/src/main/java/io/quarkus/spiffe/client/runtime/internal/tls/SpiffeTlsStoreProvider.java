package io.quarkus.spiffe.client.runtime.internal.tls;

import static io.smallrye.common.expression.Expression.Flag.LENIENT_SYNTAX;
import static io.smallrye.common.expression.Expression.Flag.NO_TRIM;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import org.jboss.logging.Logger;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.spiffe.client.SpiffeConnectionException;
import io.quarkus.spiffe.client.runtime.internal.SpiffeValidator;
import io.quarkus.spiffe.svid.x509.WorkloadCertificateDocument;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.spiffe.svid.x509.X509SvidClient;
import io.quarkus.tls.KeyStoreAndKeyCertOptions;
import io.quarkus.tls.KeyStoreProvider;
import io.quarkus.tls.TrustStoreAndTrustOptions;
import io.quarkus.tls.TrustStoreProvider;
import io.smallrye.common.expression.Expression;
import io.smallrye.config.Config;
import io.vertx.core.Vertx;

public class SpiffeTlsStoreProvider implements KeyStoreProvider, TrustStoreProvider {

    private static final Logger LOG = Logger.getLogger(SpiffeTlsStoreProvider.class);

    private final SpiffeKeyManager keyManager;
    private final SpiffeTrustManager trustManager;

    protected SpiffeTlsStoreProvider(String tlsConfigurationName, String spiffeId) {
        this.keyManager = new SpiffeKeyManager(tlsConfigurationName);
        this.trustManager = new SpiffeTrustManager(tlsConfigurationName, resolveSpiffeId(tlsConfigurationName, spiffeId));
    }

    // the service started after the TLS registry: fetches the first X.509-SVID, keeps it refreshed, stops at shutdown
    public static void start(Vertx vertx, Duration refreshPeriod, Consumer<Runnable> onStop,
            Consumer<WorkloadCertificateDocument> onComplete,
            Consumer<Throwable> onFailure, X509SvidClient x509SvidClient) {
        new X509SvidCachingClient(x509SvidClient).initialize(vertx, refreshPeriod, onStop, onFailure, onComplete);
    }

    @Override
    public KeyStoreAndKeyCertOptions getKeyStore(Vertx vertx) {
        // no raw store on purpose, the key manager reads the current X.509-SVID on every handshake
        return new KeyStoreAndKeyCertOptions(null, keyManager);
    }

    @Override
    public TrustStoreAndTrustOptions getTrustStore(Vertx vertx) {
        // no raw store on purpose, a raw trust store cannot enforce the SPIFFE ID authorization
        return new TrustStoreAndTrustOptions(null, trustManager);
    }

    private static String resolveSpiffeId(String tlsConfigurationName, String spiffeId) {
        if (spiffeId == null || !spiffeId.contains("${")) {
            return spiffeId;
        }
        Config config = Config.get();
        String resolved = Expression.compile(spiffeId, LENIENT_SYNTAX, NO_TRIM).evaluate((context, builder) -> {
            Optional<String> value = config.getOptionalValue(context.getKey(), String.class);
            if (value.isPresent()) {
                builder.append(value.get());
            } else if (context.hasDefault()) {
                context.expandDefault();
            } else {
                throw new ConfigurationException("Could not expand '" + context.getKey() + "' in the SPIFFE ID '"
                        + spiffeId + "' of the TLS configuration '" + tlsConfigurationName + "'",
                        Set.of(context.getKey()));
            }
        });
        LOG.debugf("The SPIFFE ID '%s' of the TLS configuration '%s' resolved to '%s'", spiffeId, tlsConfigurationName,
                resolved);
        // literals were validated by the SPIFFE client processor at build time, an expanded value only exists now
        if (!X509Svid.SAME_TRUST_DOMAIN.equals(resolved)) {
            try {
                SpiffeValidator.validateSpiffeId(resolved);
            } catch (SpiffeConnectionException e) {
                throw new ConfigurationException("Invalid peer SPIFFE ID '" + resolved + "' of the TLS configuration '"
                        + tlsConfigurationName + "': " + e.getMessage(), e);
            }
        }
        return resolved;
    }
}
