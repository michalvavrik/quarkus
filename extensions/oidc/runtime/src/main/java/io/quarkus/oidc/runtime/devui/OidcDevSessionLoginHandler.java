package io.quarkus.oidc.runtime.devui;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.URLEncoder;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;

final class OidcDevSessionLoginHandler implements Handler<RoutingContext> {

    private static final String REDIRECT_URI_PARAM = "oidc-provider-redirect-uri";

    /**
     * Quarkus OIDC provider card page URI.
     */
    private volatile String providerRedirectUri;

    @Override
    public void handle(RoutingContext rc) {
        // this method enforces authentication and redirects back to the original page
        // it is used when you click on the "login" button

        if (redirectUriMissing(rc)) {
            // our OIDC provider page JS should set this param
            rc.fail(500, new IllegalStateException("Query param 'oidc-provider-redirect-uri' is missing"));
            return;
        }

        HttpAuthenticator httpAuthenticator = rc.get(HttpAuthenticator.class.getName());
        if (httpAuthenticator != null) {
            QuarkusHttpUser
                    .getSecurityIdentity(rc, null)
                    .onItem().transformToUni(identity -> {
                        if (identity != null && !identity.isAnonymous()) {
                            // most likely no credentials and we need to send challenge
                            return Uni.createFrom().item(identity);
                        } else {
                            return Uni.createFrom().failure(new UnauthorizedException());
                        }
                    })
                    .subscribe().with(identity -> redirectBackToOidcProviderCardPage(rc, null),
                            ignored -> httpAuthenticator.sendChallenge(rc).subscribe().with(challengeResult -> {
                                // challenge redirecting to OIDC provider
                                if (!rc.response().ended()) {
                                    rc.response().end();
                                }
                            }, challengeFailure -> {
                                // this shouldn't happen, illegal state
                                if (!rc.response().ended()) {
                                    redirectBackToOidcProviderCardPage(rc, challengeFailure.getMessage());
                                }
                            }));
        } else {
            // this will only happen if there is a bug in Quarkus
            redirectBackToOidcProviderCardPage(rc, "Failed to authenticate as HttpAuthenticator is missing");
        }
    }

    private boolean redirectUriMissing(RoutingContext rc) {
        if (providerRedirectUri == null) {
            final String requestRedirectUri = rc.request().getParam(REDIRECT_URI_PARAM);
            if (requestRedirectUri == null) {
                return true;
            } else {
                providerRedirectUri = requestRedirectUri;
            }
        }
        return false;
    }

    private void redirectBackToOidcProviderCardPage(RoutingContext rc, String errorDescription) {
        final String oidcProviderCardPage;
        if (errorDescription != null) {
            oidcProviderCardPage = providerRedirectUri + "?error_description=" + URLEncoder.encode(errorDescription, UTF_8);
        } else {
            oidcProviderCardPage = providerRedirectUri;
        }
        rc
                .response()
                .setStatusCode(HttpResponseStatus.FOUND.code())
                .putHeader(HttpHeaders.LOCATION, oidcProviderCardPage)
                .end();
    }
}
