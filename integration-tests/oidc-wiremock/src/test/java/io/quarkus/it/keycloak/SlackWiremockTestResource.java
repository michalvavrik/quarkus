package io.quarkus.it.keycloak;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import java.io.Closeable;

import org.jboss.logging.Logger;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.matching.AnythingPattern;

public class SlackWiremockTestResource implements Closeable {

    private static final Logger LOG = Logger.getLogger(SlackWiremockTestResource.class);
    private final WireMockServer server;

    SlackWiremockTestResource() {
        var config = wireMockConfig().port(8188).globalTemplating(true);
        this.server = new WireMockServer(config);
        this.server.start();
        configureStubs();
    }

    private void configureStubs() {
        server.stubFor(
                get(urlEqualTo("/.well-known/openid-configuration"))
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
                get(urlEqualTo("/openid/connect/authorize"))
                        .withQueryParam("response_type", equalTo("code"))
                        .withQueryParam("client_id", equalTo("7917304849541.7920910519717"))
                        .withQueryParam("scope", containing("openid"))
                        .withQueryParam("scope", containing("email"))
                        .withQueryParam("scope", containing("profile"))
                        .withQueryParam("scope", containing("profile"))
                        .withQueryParam("redirect_uri", equalTo("https%3A%2F%2Flocalhost%3A8443%2F"))
                        .withQueryParam("state", new AnythingPattern())
                        .withQueryParam("team", equalTo("quarkus-oidc-slack-demo"))
                        .willReturn(aResponse()
                                .withStatus(302)
                                .withHeader("Set-Cookie", "{{request.headers.Set-Cookie}}")
                                .withHeader("Content-Type", "text/html")
                                .withHeader("Location", "https://localhost:8443?code=7917304849541.79239831"
                                        + "24323.1f4c41812b286422cbce183a9f083fa58f7c2761c281c2be483a376694f56274&state"
                                        + "={{request.query.state}}")
                                .withBody("")));

        server.stubFor(
                get(urlEqualTo("/openid/connect/keys"))
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\n" +
                                        "  \"keys\" : [\n" +
                                        "    {\n" +
                                        "      \"kid\": \"1\",\n" +
                                        "      \"kty\":\"RSA\",\n" +
                                        "      \"n\":\"iJw33l1eVAsGoRlSyo-FCimeOc-AaZbzQ2iESA3Nkuo3TFb1zIkmt0kzlnWVGt48dkaIl13Vdefh9hqw_r9yNF8xZqX1fp0PnCWc5M_TX_ht5fm9y0TpbiVmsjeRMWZn4jr3DsFouxQ9aBXUJiu26V0vd2vrECeeAreFT4mtoHY13D2WVeJvboc5mEJcp50JNhxRCJ5UkY8jR_wfUk2Tzz4-fAj5xQaBccXnqJMu_1C6MjoCEiB7G1d13bVPReIeAGRKVJIF6ogoCN8JbrOhc_48lT4uyjbgnd24beatuKWodmWYhactFobRGYo5551cgMe8BoxpVQ4to30cGA0qjQ\",\n"
                                        +
                                        "      \"e\":\"AQAB\"\n" +
                                        "    }\n" +
                                        "  ]\n" +
                                        "}")));
    }

    @Override
    public void close() {
        server.stop();
        LOG.info("Keycloak was shut down");
    }

}
