package io.quarkus.oidc;

import io.vertx.ext.web.RoutingContext;

/**
 * When a DPoP proof must include a nonce, register an implementation of this interface as a CDI bean
 * to provide and validate a nonce value.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-resource-server-provided-no">RFC 9449</a>
 */
public interface DPoPNonceProvider {

    /**
     * Provides a nonce that must be included in the DPoP proof as the "nonce" claim.
     *
     * @return resource server nonce
     * @deprecated use {@link #getNonce(DPoPNonceContext)} instead
     */
    @Deprecated(since = "4.0", forRemoval = true)
    default String getNonce() {
        throw new UnsupportedOperationException("Implement getNonce(DPoPNonceContext) instead");
    }

    /**
     * Determines if a DPoP proof nonce is valid. Implementations must check that this nonce exists and has not expired.
     *
     * @param nonce DPoP proof nonce
     * @return true if the `nonce` is valid
     * @deprecated use {@link #isValid(DPoPNonceContext)} instead
     */
    @Deprecated(since = "4.0", forRemoval = true)
    default boolean isValid(String nonce) {
        throw new UnsupportedOperationException("Implement isValid(DPoPProofContext) instead");
    }

    /**
     * Provides a nonce that must be included in the DPoP proof as the "nonce" claim.
     * <p>
     * {@link DPoPNonceContext#jti()} may come from an unverified proof (for example, when the initial DPoP proof
     * does not include a nonce claim), so use this property with care to log or record the jti value before verification.
     * {@link DPoPNonceContext#nonce()} is the previous nonce which was deemed invalid by {@link #isValid(DPoPNonceContext)},
     * or {@code null} if the DPoP proof did not have the {@code nonce} claim.
     *
     * @param context context giving access to the unverified proof jti, the current request and tenant configuration
     * @return resource server nonce; if this method returns null, no DPoP-Nonce HTTP header is added to the response and a
     *         standard 401 challenge is returned without requesting a nonce
     */
    default String getNonce(DPoPNonceContext context) {
        return getNonce();
    }

    /**
     * Determines if a DPoP proof is valid. Implementations must check that this nonce exists, has not expired
     * and wasn't already used with this jti.
     *
     * @param context context giving access to the DPoP proof nonce and jti values, the current request and the tenant
     *        configuration
     * @return true if the DPoP proof nonce is valid and the proof has not been replayed
     */
    default boolean isValid(DPoPNonceContext context) {
        return isValid(context.nonce());
    }

    record DPoPNonceContext(RoutingContext routingContext, OidcTenantConfig tenantConfig, String jti, String nonce) {
    }
}
