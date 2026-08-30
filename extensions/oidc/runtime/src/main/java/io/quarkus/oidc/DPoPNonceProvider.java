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
     * @deprecated use {@link #isValid(DPoPProofContext)} instead
     */
    @Deprecated(since = "4.0", forRemoval = true)
    default boolean isValid(String nonce) {
        throw new UnsupportedOperationException("Implement isValid(DPoPProofContext) instead");
    }

    /**
     * Provides a nonce that must be included in the DPoP proof as the "nonce" claim.
     *
     * @param context context giving access to the current request and tenant configuration
     * @return resource server nonce
     */
    default String getNonce(DPoPNonceContext context) {
        return getNonce();
    }

    /**
     * Determines if a DPoP proof is valid. Implementations must check that the {@link DPoPProofContext#nonce()} exists
     * and has not expired. Because the {@link DPoPProofContext#jti()} value is provided only after the DPoP proof has
     * been fully verified, implementations can also use it to detect and reject replayed DPoP proofs, for example when
     * the same nonce value is accepted more than once.
     *
     * @param context context giving access to the DPoP proof nonce and jti values, the current request and the tenant
     *        configuration
     * @return true if the DPoP proof nonce is valid and the proof has not been replayed
     */
    default boolean isValid(DPoPProofContext context) {
        return isValid(context.nonce());
    }

    record DPoPProofContext(String nonce, String jti, RoutingContext routingContext, OidcTenantConfig tenantConfig) {
    }

    record DPoPNonceContext(RoutingContext routingContext, OidcTenantConfig tenantConfig) {
    }
}
