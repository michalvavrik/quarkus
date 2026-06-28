package io.quarkus.spiffe.client.api;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;

/**
 * Client for the SPIFFE Workload API.
 */
public interface SpiffeClient {

    /**
     * Fetches a single JWT-SVID from the Workload API. Suitable for workloads with one registered
     * identity. When multiple identities are authorized, the returned SVID is arbitrarily chosen;
     * use {@link #fetchJwtSvids(JwtSvidRequest)} with {@link JwtSvid#hint()} or
     * {@link JwtSvidRequest#spiffeId()} to select a specific identity instead.
     * <p>
     *
     * @param request the fetch parameters, including at least one audience; never null
     * @return a {@link Uni} that emits a single {@link JwtSvid}, never {@code null}; fails with
     *         {@link SpiffeAuthorizationException} when the workload is not authorized for any
     *         identity, or {@link SpiffeConnectionException} when the SPIRE Agent is unreachable
     */
    Uni<JwtSvid> fetchJwtSvid(JwtSvidRequest request);

    /**
     * Fetches all JWT-SVIDs that this workload is authorized for. A workload may have multiple
     * SPIFFE identities if it matches several SPIRE registration entries. Use
     * {@link JwtSvid#hint()} to distinguish between them.
     *
     * @param request the fetch parameters, including at least one audience; never null
     * @return a {@link Multi} that emits at least one {@link JwtSvid}; fails with
     *         {@link SpiffeAuthorizationException} when the workload is not authorized for any
     *         identity, or {@link SpiffeConnectionException} when the SPIRE Agent is unreachable
     */
    Multi<JwtSvid> fetchJwtSvids(JwtSvidRequest request);

}
