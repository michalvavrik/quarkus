package io.quarkus.it.keycloak;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import java.io.Closeable;

import org.jboss.logging.Logger;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.matching.AnythingPattern;

public class SlackWiremockTestResource implements Closeable {

    private static final Logger LOG = Logger.getLogger(SlackWiremockTestResource.class);
    private static final int PORT = 8188;
    private final WireMockServer server;

    SlackWiremockTestResource() {
        var config = wireMockConfig().port(PORT).globalTemplating(true);
        this.server = new WireMockServer(config);
        LOG.info("Starting Slack mock on port " + PORT);
        this.server.start();
        configureStubs();
    }

    private void configureStubs() {
        server.stubFor(
                get(urlMatching("/.well-known/openid-configuration.*"))
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "application/json")
                                .withBody(
                                        """
                                                {
                                                    "issuer": "http://localhost:8188",
                                                    "authorization_endpoint": "http://localhost:8188/openid/connect/authorize",
                                                    "token_endpoint": "http://localhost:8188/api/openid.connect.token",
                                                    "userinfo_endpoint": "http://localhost:8188/api/openid.connect.userInfo",
                                                    "jwks_uri": "http://localhost:8188/openid/connect/keys",
                                                    "scopes_supported": ["openid","profile","email"],
                                                    "response_types_supported": ["code"],
                                                    "response_modes_supported": ["form_post"],
                                                    "grant_types_supported": ["authorization_code"],
                                                    "subject_types_supported": ["public"],
                                                    "id_token_signing_alg_values_supported": ["RS256"],
                                                    "claims_supported": ["sub","auth_time","iss"],
                                                    "claims_parameter_supported": false,
                                                    "request_parameter_supported": false,
                                                    "request_uri_parameter_supported": true,
                                                    "token_endpoint_auth_methods_supported": ["client_secret_post","client_secret_basic"]
                                                }
                                                """)));

        server.stubFor(
                get(urlMatching("/openid/connect/authorize.*"))
                        .withQueryParam("response_type", equalTo("code"))
                        .withQueryParam("client_id", equalTo("7917304849541.7920910519717"))
                        .withQueryParam("scope", containing("openid"))
                        .withQueryParam("scope", containing("email"))
                        .withQueryParam("scope", containing("profile"))
                        .withQueryParam("scope", containing("profile"))
                        .withQueryParam("redirect_uri", equalTo("http://localhost:8081/code-flow-slack"))
                        .withQueryParam("state", new AnythingPattern())
                        .withQueryParam("team", equalTo("quarkus-oidc-slack-demo"))
                        .willReturn(aResponse()
                                .withStatus(302)
                                .withHeader("Set-Cookie", "{{request.headers.Set-Cookie}}")
                                .withHeader("Content-Type", "text/html")
                                .withHeader("Location", "http://localhost:8081?code=7917304849541.79239831"
                                        + "24323.1f4c41812b286422cbce183a9f083fa58f7c2761c281c2be483a376694f56274&state"
                                        + "={{request.query.state}}")
                                .withBody("")));

        server.stubFor(
                get(urlMatching("/openid/connect/keys.*"))
                        .willReturn(aResponse()
                                .withHeader("Set-Cookie", "{{request.headers.Set-Cookie}}")
                                .withHeader("Content-Type", "application/json")
                                .withBody(
                                        """
                                                {
                                                  "keys": [
                                                    {
                                                      "e": "AQAB",
                                                      "n": "zQqzXfb677bpMKw0idKC5WkVLyqk04PWMsWYJDKqMUUuu_PmzdsvXBfHU7tcZiNoHDuVvGDqjqnkLPEzjXnaZY0DDDHvJKS0JI8fkxIfV1kNy3DkpQMMhgAwnftUiSXgb5clypOmotAEm59gHPYjK9JHBWoHS14NYEYZv9NVy0EkjauyYDSTz589aiKU5lA-cePG93JnqLw8A82kfTlrJ1IIJo2isyBGANr0YzR-d3b_5EvP7ivU7Ph2v5JcEUHeiLSRzIzP3PuyVFrPH659Deh-UAsDFOyJbIcimg9ITnk5_45sb_Xcd_UN6h5I7TGOAFaJN4oi4aaGD4elNi_K1Q",
                                                      "kty": "RSA",
                                                      "kid": "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY",
                                                      "alg": "RS256"
                                                    }
                                                  ]
                                                }
                                                """)));
    }

    @Override
    public void close() {
        server.stop();
        LOG.info("Slack mock was shut down");
    }

}
