package io.quarkus.spiffe.client.api;

import java.util.Set;

/**
 * Parameters for fetching JWT-SVIDs from the SPIFFE Workload API.
 */
public sealed interface JwtSvidRequest {

    /**
     * Returns the audience values that the SPIRE Server embeds into the JWT {@code aud} claim.
     * Never null or empty.
     */
    Set<String> audiences();

    /**
     * Returns the SPIFFE ID filter, or {@code null} to fetch SVIDs for all authorized identities.
     */
    String spiffeId();

    /**
     * Creates a request for the given audiences without a SPIFFE ID filter.
     *
     * @param audiences one or more audience values
     */
    static JwtSvidRequest forAudience(String... audiences) {
        return new JwtSvidRequestBuilder().audiences(audiences).build();
    }

    /**
     * Returns a new builder for constructing a request with optional parameters.
     */
    static JwtSvidRequestBuilder builder() {
        return new JwtSvidRequestBuilder();
    }

    /**
     * Builder for {@link JwtSvidRequest} instances.
     */
    final class JwtSvidRequestBuilder {

        private String spiffeId;
        private Set<String> audiences;

        private JwtSvidRequestBuilder() {
            this.spiffeId = null;
            this.audiences = null;
        }

        /**
         * Restricts the request to a specific SPIFFE ID. When omitted, the Workload API returns
         * SVIDs for all identities authorized for this workload.
         */
        public JwtSvidRequestBuilder spiffeId(String spiffeId) {
            if (spiffeId == null) {
                throw new IllegalArgumentException("SPIFFE id must not be null");
            }
            if (spiffeId.isBlank()) {
                throw new IllegalArgumentException("SPIFFE id must not be blank");
            }
            this.spiffeId = spiffeId;
            return this;
        }

        /**
         * Sets a single audience value, replacing any previously set audiences.
         * To specify multiple audiences, use {@link #audiences(Set)} instead.
         */
        public JwtSvidRequestBuilder audience(String audience) {
            return audiences(audience);
        }

        /**
         * Sets multiple audience values, replacing any previously set audiences.
         */
        public JwtSvidRequestBuilder audiences(Set<String> audiences) {
            if (audiences == null) {
                throw new IllegalArgumentException("Audiences must not be null");
            }
            return audiences(audiences.toArray(String[]::new));
        }

        /**
         * Builds an immutable {@link JwtSvidRequest} from the configured parameters.
         *
         * @throws IllegalStateException if no audience was set
         */
        public JwtSvidRequest build() {
            if (audiences == null) {
                throw new IllegalStateException("Primary audience parameter is mandatory, but no audience was specified");
            }
            return new JwtSvidRequestImpl(spiffeId, audiences);
        }

        private JwtSvidRequestBuilder audiences(String... audiences) {
            if (audiences == null) {
                throw new IllegalArgumentException("Audiences must not be null");
            }
            if (audiences.length == 0) {
                throw new IllegalArgumentException("No audiences specified, but the primary audience parameter is mandatory");
            }
            for (String a : audiences) {
                if (a == null) {
                    throw new IllegalArgumentException("Audience must not be null");
                }
                if (a.isBlank()) {
                    throw new IllegalArgumentException("Audience must not be blank");
                }
            }
            this.audiences = Set.of(audiences);
            return this;
        }

        record JwtSvidRequestImpl(String spiffeId, Set<String> audiences) implements JwtSvidRequest {
        }
    }
}
