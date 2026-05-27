package io.quarkus.vertx.http.runtime;

import static io.quarkus.vertx.http.runtime.TrustedProxyCheck.TrustedProxyCheckBuilder.builder;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.vertx.http.runtime.ProxyConfig.TrustedProxyConfig;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.http.HttpServerRequest;

/**
 * Applies a {@link TrustedProxyCheck} based on {@link ProxyConfig} when the proxy address forwarding is enabled.
 */
public final class ForwardingProxyHandler {

    public static Handler<HttpServerRequest> create(ProxyConfig proxyConfig, ClientAuth clientAuth,
            Optional<String> tlsConfigName, Supplier<Vertx> vertx, Handler<HttpServerRequest> root,
            String configPrefix) {
        final boolean allowForwarded = proxyConfig.allowForwarded();
        final boolean allowXForwarded = proxyConfig.allowXForwarded().orElse(!allowForwarded);
        final boolean hasClientAuthTrustCheck = !proxyConfig.trustedProxy().isEmpty();
        final boolean hasHostTrustCheck = proxyConfig.trustedProxies().filter(Predicate.not(List::isEmpty)).isPresent();

        validateTrustedProxyConfig(clientAuth, allowXForwarded, allowForwarded, hasClientAuthTrustCheck, hasHostTrustCheck,
                configPrefix);

        ForwardingProxyOptions options = ForwardingProxyOptions.from(proxyConfig);
        if (hasHostTrustCheck) {
            return new ForwardedProxyHandler(builder(proxyConfig.trustedProxies().get()), vertx, root, options);
        } else if (hasClientAuthTrustCheck) {
            return new RequestForwardingProxyHandler(
                    allowConfiguredClients(proxyConfig.trustedProxy(), tlsConfigName, configPrefix), root, options);
        }
        return new RequestForwardingProxyHandler(allowAll(), root, options);
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> allowConfiguredClients(
            List<TrustedProxyConfig> trustedProxyConfigs, Optional<String> tlsConfigName, String configPrefix) {
        final boolean checkRdn = trustedProxyConfigs.stream().anyMatch(c -> c.subjectDn().isPresent());
        if (checkRdn) {
            final boolean checkTruststore = trustedProxyConfigs.stream().anyMatch(c -> c.truststoreAlias().isPresent());
            if (checkTruststore) {
                return checkBothRDNsAndTruststore(trustedProxyConfigs, tlsConfigName, configPrefix);
            }
            return checkOnlyRDNs(trustedProxyConfigs, configPrefix);
        }
        return onlyCheckTruststoreAliases(trustedProxyConfigs, tlsConfigName, configPrefix);
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> checkOnlyRDNs(List<TrustedProxyConfig> trustedProxyConfigs,
            String configPrefix) {
        return checkRDNs(trustedProxyConfigs.stream().map(TrustedProxyConfig::subjectDn).filter(Optional::isPresent)
                .map(Optional::get).toList(), configPrefix);
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> onlyCheckTruststoreAliases(
            List<TrustedProxyConfig> trustedProxyConfigs, Optional<String> tlsConfigName, String configPrefix) {
        List<String> aliases = trustedProxyConfigs.stream()
                .map(TrustedProxyConfig::truststoreAlias)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
        return createTrustManagerHolder(aliases, tlsConfigName, configPrefix);
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> checkBothRDNsAndTruststore(
            List<TrustedProxyConfig> trustedProxyConfigs, Optional<String> tlsConfigName, String configPrefix) {
        return trustedProxyConfigs.stream()
                .map(c -> {
                    Function<HttpServerRequest, TrustedProxyCheck> requestToCheckFunction = null;
                    if (c.truststoreAlias().isPresent()) {
                        var aliasAsList = List.of(c.truststoreAlias().get());
                        requestToCheckFunction = createTrustManagerHolder(aliasAsList, tlsConfigName, configPrefix);
                    }
                    if (c.subjectDn().isPresent()) {
                        var subjectDnAsList = List.of(c.subjectDn().get());
                        if (requestToCheckFunction == null) {
                            requestToCheckFunction = checkRDNs(subjectDnAsList, configPrefix);
                        } else {
                            requestToCheckFunction = logicalAnd(requestToCheckFunction,
                                    checkRDNs(subjectDnAsList, configPrefix));
                        }
                    }
                    if (requestToCheckFunction == null) {
                        throw new ConfigurationException(
                                "Each '" + configPrefix + ".proxy.trusted-proxy' entry must have at least "
                                        + "'subject-dn' or 'truststore-alias' configured");
                    }
                    return requestToCheckFunction;
                })
                .reduce(ForwardingProxyHandler::logicalOr)
                .orElseThrow();
    }

    private static TrustManagerHolder createTrustManagerHolder(List<String> aliases, Optional<String> tlsConfigName,
            String configPrefix) {
        var container = Arc.requireContainer();
        TlsConfigurationRegistry registry = container.select(TlsConfigurationRegistry.class).get();
        TlsConfiguration tlsConfig = tlsConfigName
                .flatMap(registry::get)
                .or(registry::getDefault)
                .orElseThrow(() -> new ConfigurationException(
                        "'" + configPrefix + ".proxy.trusted-proxy[*].truststore-alias' requires the server "
                                + "to use the TLS registry. Configure 'quarkus.tls' truststore properties."));

        TrustManagerHolder holder = new TrustManagerHolder(tlsConfig, aliases);

        HttpCertificateUpdateEventListener listener = container.select(HttpCertificateUpdateEventListener.class).get();
        listener.register(holder::onCertificateUpdate, tlsConfig.getName());

        return holder;
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> checkRDNs(List<String> subjectDns, String configPrefix) {
        return new Function<>() {

            private final List<List<Rdn>> trustedDns = subjectDns.stream()
                    .map(dn -> toRdns(dn, configPrefix)).toList();

            @Override
            public TrustedProxyCheck apply(HttpServerRequest request) {
                return TrustedProxyCheck.createTrustedProxyDnCheck(request, trustedDns);
            }
        };
    }

    private static List<Rdn> toRdns(String dn, String configPrefix) {
        try {
            var x500PrincipalName = new X500Principal(dn).getName();
            return List.copyOf(new LdapName(x500PrincipalName).getRdns());
        } catch (IllegalArgumentException | InvalidNameException e) {
            throw new ConfigurationException(
                    "Invalid '" + configPrefix + ".proxy.trusted-proxy[*].subject-dn' value '" + dn
                            + "': not a valid RFC 2253 Distinguished Name",
                    e);
        }
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> allowAll() {
        return new Function<>() {

            private final TrustedProxyCheck allowAll = TrustedProxyCheck.allowAll();

            @Override
            public TrustedProxyCheck apply(HttpServerRequest request) {
                return allowAll;
            }
        };
    }

    private static void validateTrustedProxyConfig(ClientAuth clientAuth, boolean allowXForwarded, boolean allowForwarded,
            boolean hasClientAuthTrustCheck, boolean hasHostTrustCheck, String configPrefix) {
        if (!hasClientAuthTrustCheck) {

            if (hasHostTrustCheck && !allowXForwarded && !allowForwarded) {
                throw new ConfigurationException(
                        "'" + configPrefix + ".proxy.trusted-proxies' requires '" + configPrefix
                                + ".proxy.allow-forwarded' "
                                + "or '" + configPrefix + ".proxy.allow-x-forwarded' to be enabled");
            }
        } else {

            if (hasHostTrustCheck) {
                throw new ConfigurationException(
                        "'" + configPrefix + ".proxy.trusted-proxies' and '" + configPrefix
                                + ".proxy.trusted-proxy' are mutually exclusive");
            }

            if (clientAuth == ClientAuth.NONE) {
                throw new ConfigurationException(
                        "'" + configPrefix + ".proxy.trusted-proxy' requires '" + configPrefix
                                + ".ssl.client-auth' to be set "
                                + "to 'request' or 'required'");
            }

            if (!allowXForwarded && !allowForwarded) {
                throw new ConfigurationException(
                        "'" + configPrefix + ".proxy.trusted-proxy' requires '" + configPrefix
                                + ".proxy.allow-forwarded' "
                                + "or '" + configPrefix + ".proxy.allow-x-forwarded' to be enabled");
            }
        }
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> logicalAnd(Function<HttpServerRequest, TrustedProxyCheck> a,
            Function<HttpServerRequest, TrustedProxyCheck> b) {
        return new Function<HttpServerRequest, TrustedProxyCheck>() {
            @Override
            public TrustedProxyCheck apply(HttpServerRequest request) {
                if (a.apply(request).isProxyAllowed() && b.apply(request).isProxyAllowed()) {
                    return TrustedProxyCheck.allowAll();
                }
                return TrustedProxyCheck.denyAll();
            }
        };
    }

    private static Function<HttpServerRequest, TrustedProxyCheck> logicalOr(Function<HttpServerRequest, TrustedProxyCheck> a,
            Function<HttpServerRequest, TrustedProxyCheck> b) {
        return new Function<HttpServerRequest, TrustedProxyCheck>() {
            @Override
            public TrustedProxyCheck apply(HttpServerRequest request) {
                if (a.apply(request).isProxyAllowed() || b.apply(request).isProxyAllowed()) {
                    return TrustedProxyCheck.allowAll();
                }
                return TrustedProxyCheck.denyAll();
            }
        };
    }

    private static final class TrustManagerHolder implements Function<HttpServerRequest, TrustedProxyCheck> {

        private static final Logger LOG = Logger.getLogger(TrustManagerHolder.class);

        private final List<String> aliases;
        private volatile List<X509TrustManager> trustManagers;

        TrustManagerHolder(TlsConfiguration tlsConfig, List<String> aliases) {
            this.aliases = aliases;
            this.trustManagers = buildTrustManagers(tlsConfig.getTrustStore());
        }

        void onCertificateUpdate(TlsConfiguration tlsConfig) {
            LOG.debug("Rebuilding trusted proxy trust managers after certificate update");
            try {
                this.trustManagers = buildTrustManagers(tlsConfig.getTrustStore());
            } catch (Exception e) {
                LOG.error("Failed to rebuild trusted proxy trust managers, rejecting all proxies until next successful reload",
                        e);
                this.trustManagers = List.of();
            }
        }

        @Override
        public TrustedProxyCheck apply(HttpServerRequest event) {
            return TrustedProxyCheck.createTruststoreCheck(event, trustManagers);
        }

        private List<X509TrustManager> buildTrustManagers(KeyStore trustStore) {
            return aliases.stream()
                    .map(alias -> {
                        try {
                            Certificate cert = trustStore.getCertificate(alias);
                            if (cert == null) {
                                throw new ConfigurationException(
                                        "Truststore alias '" + alias + "' not found in the HTTP server truststore");
                            }
                            KeyStore singleCertKs = KeyStore.getInstance(KeyStore.getDefaultType());
                            singleCertKs.load(null, null);
                            singleCertKs.setCertificateEntry(alias, cert);
                            TrustManagerFactory tmf = TrustManagerFactory
                                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            tmf.init(singleCertKs);
                            for (TrustManager tm : tmf.getTrustManagers()) {
                                if (tm instanceof X509TrustManager x509TrustManager) {
                                    return x509TrustManager;
                                }
                            }
                            throw new IllegalStateException("No X509TrustManager produced for alias '" + alias + "'");
                        } catch (ConfigurationException e) {
                            throw e;
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to build trust manager for alias '" + alias + "'", e);
                        }
                    })
                    .toList();
        }
    }

    private record RequestForwardingProxyHandler(
            Function<HttpServerRequest, TrustedProxyCheck> requestToTrustedProxyCheck, Handler<HttpServerRequest> root,
            ForwardingProxyOptions forwardingProxyOptions) implements Handler<HttpServerRequest> {

        @Override
        public void handle(HttpServerRequest event) {
            ForwardedServerRequestWrapper wrapper;
            try {
                wrapper = new ForwardedServerRequestWrapper(event, forwardingProxyOptions,
                        requestToTrustedProxyCheck.apply(event));
                @SuppressWarnings("unused")
                var unused = wrapper.authority();
            } catch (IllegalArgumentException e) {
                event.response().setStatusCode(400).end();
                return;
            }
            root.handle(wrapper);
        }
    }

}
