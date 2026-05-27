package io.quarkus.vertx.http.runtime;

import io.netty.util.AsciiString;
import io.quarkus.vertx.http.runtime.ProxyConfig.ForwardedPrecedence;

public class ForwardingProxyOptions {
    public final boolean proxyAddressForwarding;
    final boolean allowForwarded;
    final boolean allowXForwarded;
    final boolean enableForwardedHost;
    final boolean enableForwardedPrefix;
    final AsciiString forwardedHostHeader;
    final AsciiString forwardedPrefixHeader;
    final boolean strictForwardedControl;
    final ForwardedPrecedence forwardedPrecedence;
    final boolean enableTrustedProxyHeader;

    public ForwardingProxyOptions(final boolean proxyAddressForwarding,
            boolean allowForwarded,
            boolean allowXForwarded,
            boolean enableForwardedHost,
            boolean enableTrustedProxyHeader,
            AsciiString forwardedHostHeader,
            boolean enableForwardedPrefix,
            boolean strictForwardedControl,
            ForwardedPrecedence forwardedPrecedence,
            AsciiString forwardedPrefixHeader) {
        this.proxyAddressForwarding = proxyAddressForwarding;
        this.allowForwarded = allowForwarded;
        this.allowXForwarded = allowXForwarded;
        this.enableForwardedHost = enableForwardedHost;
        this.enableForwardedPrefix = enableForwardedPrefix;
        this.forwardedHostHeader = forwardedHostHeader;
        this.forwardedPrefixHeader = forwardedPrefixHeader;
        this.strictForwardedControl = strictForwardedControl;
        this.forwardedPrecedence = forwardedPrecedence;
        this.enableTrustedProxyHeader = enableTrustedProxyHeader;
    }

    static ForwardingProxyOptions from(ProxyConfig proxyConfig) {
        final boolean proxyAddressForwarding = proxyConfig.proxyAddressForwarding();
        final boolean allowForwarded = proxyConfig.allowForwarded();
        final boolean allowXForwarded = proxyConfig.allowXForwarded().orElse(!allowForwarded);
        final boolean enableForwardedHost = proxyConfig.enableForwardedHost();
        final boolean enableForwardedPrefix = proxyConfig.enableForwardedPrefix();
        final boolean enableTrustedProxyHeader = proxyConfig.enableTrustedProxyHeader();
        final boolean strictForwardedControl = proxyConfig.strictForwardedControl();
        final ForwardedPrecedence forwardedPrecedence = proxyConfig.forwardedPrecedence();
        final AsciiString forwardedPrefixHeader = AsciiString.cached(proxyConfig.forwardedPrefixHeader());
        final AsciiString forwardedHostHeader = AsciiString.cached(proxyConfig.forwardedHostHeader());

        return new ForwardingProxyOptions(proxyAddressForwarding, allowForwarded, allowXForwarded, enableForwardedHost,
                enableTrustedProxyHeader, forwardedHostHeader, enableForwardedPrefix, strictForwardedControl,
                forwardedPrecedence, forwardedPrefixHeader);
    }
}
