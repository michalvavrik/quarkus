package io.quarkus.it.keycloak;

import java.time.Duration;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.oidc.runtime.OidcProvider;
import io.quarkus.oidc.runtime.OidcProviderClientImpl;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;

@Path("/tenant-refresh")
public class TenantRefreshTokenResource {

    @Inject
    @IdToken
    JsonWebToken idToken;

    @Inject
    JsonWebToken accessToken;

    @Inject
    RefreshToken refreshToken;

    @Inject
    TenantConfigBean tenantConfigBean;

    @Inject
    OidcResource oidcResource;

    @GET
    @Path("/tenant-web-app-refresh/api/user")
    @RolesAllowed("user")
    public String checkTokens() {
        return "userName: " + idToken.getName()
                + ", idToken: " + (idToken.getRawToken() != null)
                + ", accessToken: " + (accessToken.getRawToken() != null)
                + ", accessTokenLongStringClaim: " + accessToken.getClaim("longstring")
                + ", refreshToken: " + (refreshToken.getToken() != null);
    }

    @GET
    @Path("/concurrent-token-refresh")
    @PermitAll
    public ConcurrentRefreshResult getConcurrentRefreshResult(@QueryParam("refresh_token") String originalRefreshToken,
            @QueryParam("expected_count_before") int expectedCountBefore,
            @QueryParam("expected_count_after") int expectedCountAfter) {
        var tenantConfigContext = tenantConfigBean.getStaticTenant("concurrent-token-refresh");
        OidcProviderClientImpl client = tenantConfigContext.getOidcProviderClient();
        OidcProvider oidcProvider = tenantConfigContext.provider();
        oidcResource.refreshEndpointWait = true;
        return assertCount(client, originalRefreshToken, expectedCountBefore)
                .chain(() -> Uni.join().all(
                        oidcProvider.refreshTokens(originalRefreshToken),
                        Uni.createFrom().nullItem().onItem().delayIt().by(Duration.ofMillis(300))
                                .chain(() -> assertCount(client, originalRefreshToken, expectedCountAfter))
                                .chain(() -> {
                                    var req = oidcProvider.refreshTokens(originalRefreshToken);
                                    oidcResource.refreshEndpointWait = false;
                                    return req;
                                }))
                        .andFailFast()
                        .map(result -> {
                            AuthorizationCodeTokens tokens1 = result.get(0);
                            AuthorizationCodeTokens tokens2 = result.get(1);
                            return new ConcurrentRefreshResult(tokens1.getAccessToken(), tokens2.getAccessToken());
                        })
                        .flatMap(result -> assertCount(client, originalRefreshToken, expectedCountAfter)
                                .replaceWith(result)))
                .runSubscriptionOn(Infrastructure.getDefaultExecutor())
                .await().indefinitely();
    }

    private Uni<Void> assertCount(OidcProviderClientImpl client, String refreshToken, int expectedCount) {
        return client.getRefreshTokenRequest(refreshToken)
                .map(rt -> rt == null ? 0 : 1)
                .flatMap(actualCount -> {
                    if (actualCount == expectedCount) {
                        return Uni.createFrom().voidItem();
                    } else {
                        return Uni.createFrom().failure(
                                new AssertionError(
                                        "Expected '%s' cached token refresh requests, but got '%s'".formatted(expectedCount,
                                                actualCount)));
                    }
                });
    }

    public record ConcurrentRefreshResult(String accessToken1, String accessToken2) {
    }
}
