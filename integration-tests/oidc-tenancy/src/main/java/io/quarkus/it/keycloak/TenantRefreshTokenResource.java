package io.quarkus.it.keycloak;

import java.time.Duration;

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
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.smallrye.mutiny.Uni;

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
    @RolesAllowed("user")
    public ConcurrentRefreshResult getConcurrentRefreshResult(@QueryParam("refresh_token") String originalRefreshToken) {
        OidcProvider oidcProvider = tenantConfigBean.getStaticTenant("concurrent-token-refresh").provider();
        oidcResource.refreshEndpointWait = true;
        var result = Uni.join().all(
                oidcProvider.refreshTokens(originalRefreshToken),
                Uni.createFrom().nullItem().onItem().delayIt().by(Duration.ofMillis(300))
                        .chain(() -> {
                            var req = oidcProvider.refreshTokens(originalRefreshToken);
                            oidcResource.refreshEndpointWait = false;
                            return req;
                        }))
                .andFailFast().await().indefinitely();
        AuthorizationCodeTokens tokens1 = result.get(0);
        AuthorizationCodeTokens tokens2 = result.get(1);
        return new ConcurrentRefreshResult(tokens1.getAccessToken(), tokens2.getAccessToken());
    }

    public record ConcurrentRefreshResult(String accessToken1, String accessToken2) {
    }
}
