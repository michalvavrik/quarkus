package io.quarkus.vertx.http.runtime;

import static java.lang.String.format;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.spi.Converter;
import org.jboss.logging.Logger;

import io.quarkus.runtime.configuration.CidrAddressConverter;
import io.quarkus.runtime.configuration.InetSocketAddressConverter;
import io.vertx.core.net.SocketAddress;
import io.vertx.core.net.impl.SocketAddressImpl;

/**
 * Converts proxy address into match {@link Predicate}.
 */
public final class TrustedXForwardedProxyConverter
        implements Converter<TrustedXForwardedProxyConverter.TrustedXForwardedProxyCheck> {

    private static final Logger LOG = Logger.getLogger(TrustedXForwardedProxyConverter.class);
    private static final String DOMAIN_SOCKET_NOT_SUPPORTED = "Domain socket are not supported, forward headers are going to be ignored";
    private static final Pattern CIDR_PATTERN = Pattern.compile(".+\\/\\d+");

    @Override
    public TrustedXForwardedProxyCheck convert(String proxyAddress) {
        if (CIDR_PATTERN.matcher(proxyAddress).matches()) {
            return createNewCidrCheck(proxyAddress);
        } else {
            return createNewInitSocketAddressCheck(proxyAddress);
        }
    }

    private static TrustedXForwardedProxyCheck createNewInitSocketAddressCheck(String proxyAddresses) {
        final var proxyAddress = new InetSocketAddressConverter().convert(proxyAddresses);
        final boolean doNotCheckPort = proxyAddress.getPort() == 0;
        final boolean useHostName = proxyAddress.isUnresolved();
        return new TrustedXForwardedProxyCheck() {
            @Override
            public boolean test(SocketAddress requestAddress) {
                if (requestAddress.isDomainSocket()) {
                    LOG.debug(DOMAIN_SOCKET_NOT_SUPPORTED);
                } else if (isPortOk(requestAddress)) {
                    final InetAddress requestIP = getInetAddress(requestAddress);
                    if (requestIP != null) {
                        return requestIP.equals(proxyIP());
                    }
                }
                return false;
            }

            private InetAddress proxyIP() {
                if (useHostName) {
                    return getInetAddressByHost(proxyAddress.getHostName());
                } else {
                    return proxyAddress.getAddress();
                }
            }

            private boolean isPortOk(SocketAddress requestAddress) {
                return doNotCheckPort || requestAddress.port() == proxyAddress.getPort();
            }
        };
    }

    private static TrustedXForwardedProxyCheck createNewCidrCheck(String proxyAddresses) {
        final var cidrAddress = new CidrAddressConverter().convert(proxyAddresses);
        return new TrustedXForwardedProxyCheck() {
            @Override
            public boolean test(SocketAddress address) {
                if (address.isDomainSocket()) {
                    LOG.debug(DOMAIN_SOCKET_NOT_SUPPORTED);
                } else {
                    final InetAddress ip = getInetAddress(address);
                    if (ip != null) {
                        return cidrAddress.matches(ip);
                    }
                }
                return false;
            }
        };
    }

    private static InetAddress getInetAddress(SocketAddress address) {
        InetAddress ip = ((SocketAddressImpl) address).ipAddress();
        if (ip == null) {
            ip = getInetAddressByHost(address.host());
        }
        return ip;
    }

    private static InetAddress getInetAddressByHost(String host) {
        try {
            return InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            LOG.debug(format("Failed to resolve host '%s', forward headers are going to be ignored: ", host), e);
            return null;
        }
    }

    /**
     * Wraps {@link Predicate<SocketAddress>} as currently the Config system does not support all parametrized types.
     * We should drop this interface when the Config system support improves.
     */
    interface TrustedXForwardedProxyCheck extends Predicate<SocketAddress> {

    }
}
