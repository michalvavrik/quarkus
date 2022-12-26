package io.quarkus.vertx.http.runtime;

import java.util.List;
import java.util.function.Predicate;

import io.netty.util.AsciiString;
import io.vertx.core.net.SocketAddress;

public class ForwardingProxyOptions {
    final boolean proxyAddressForwarding;
    final boolean allowForwarded;
    final boolean allowXForwarded;
    final boolean enableForwardedHost;
    final boolean enableForwardedPrefix;
    final AsciiString forwardedHostHeader;
    final AsciiString forwardedPrefixHeader;
    final List<Predicate<SocketAddress>> trustedXForwardedProxy;

    public ForwardingProxyOptions(final boolean proxyAddressForwarding,
            final boolean allowForwarded,
            final boolean allowXForwarded,
            final boolean enableForwardedHost,
            final AsciiString forwardedHostHeader,
            final boolean enableForwardedPrefix,
            final AsciiString forwardedPrefixHeader,
            List<Predicate<SocketAddress>> trustedXForwardedProxy) {
        this.proxyAddressForwarding = proxyAddressForwarding;
        this.allowForwarded = allowForwarded;
        this.allowXForwarded = allowXForwarded;
        this.enableForwardedHost = enableForwardedHost;
        this.enableForwardedPrefix = enableForwardedPrefix;
        this.forwardedHostHeader = forwardedHostHeader;
        this.forwardedPrefixHeader = forwardedPrefixHeader;
        this.trustedXForwardedProxy = trustedXForwardedProxy;
    }

    public static ForwardingProxyOptions from(HttpConfiguration httpConfiguration) {
        final boolean proxyAddressForwarding = httpConfiguration.proxy.proxyAddressForwarding;
        final boolean allowForwarded = httpConfiguration.proxy.allowForwarded;
        final boolean allowXForwarded = httpConfiguration.proxy.allowXForwarded.orElse(!allowForwarded);

        final boolean enableForwardedHost = httpConfiguration.proxy.enableForwardedHost;
        final boolean enableForwardedPrefix = httpConfiguration.proxy.enableForwardedPrefix;
        final AsciiString forwardedPrefixHeader = AsciiString.cached(httpConfiguration.proxy.forwardedPrefixHeader);
        final AsciiString forwardedHostHeader = AsciiString.cached(httpConfiguration.proxy.forwardedHostHeader);

        final List<Predicate<SocketAddress>> trustedXForwardedProxies = httpConfiguration.proxy.trustedXForwardedProxies
                .isPresent() ? List.copyOf(httpConfiguration.proxy.trustedXForwardedProxies.get()) : List.of();

        return new ForwardingProxyOptions(proxyAddressForwarding, allowForwarded, allowXForwarded, enableForwardedHost,
                forwardedHostHeader, enableForwardedPrefix, forwardedPrefixHeader, trustedXForwardedProxies);
    }
}
