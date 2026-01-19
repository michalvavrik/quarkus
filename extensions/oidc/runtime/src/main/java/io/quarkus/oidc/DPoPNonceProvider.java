package io.quarkus.oidc;

/**
 * Users can choose to provide a nonce value to be included in DPoP proofs sent to them, by providing
 * the {@link jakarta.inject.Singleton} or the {@link jakarta.enterprise.context.ApplicationScoped} CDI bean
 * implementing this interface.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-resource-server-provided-no">RFC 9449</a>
 */
public interface DPoPNonceProvider {

    /**
     * Provides a resource server nonce that must be included in the DPoP proof as the "nonce" claim.
     *
     * @return resource server nonce
     */
    String getNonce();

}
