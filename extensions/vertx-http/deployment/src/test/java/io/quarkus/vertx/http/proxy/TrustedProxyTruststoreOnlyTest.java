package io.quarkus.vertx.http.proxy;

import static io.quarkus.vertx.http.proxy.AbstractTrustedProxyDnTest.PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.net.URL;

import jakarta.inject.Inject;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.ForwardedHandlerInitializer;
import io.restassured.RestAssured;
import io.smallrye.certs.Format;
import io.smallrye.certs.junit5.Alias;
import io.smallrye.certs.junit5.Certificate;
import io.smallrye.certs.junit5.Certificates;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.PfxOptions;

@Certificates(certificates = {
        @Certificate(name = TrustedProxyTruststoreOnlyTest.CERT_NAME, password = PASSWORD, formats = {
                Format.PKCS12 }, subjectAlternativeNames = "DNS:localhost", client = true, aliases = {
                        @Alias(name = "proxy", client = true, cn = "proxy-client", password = PASSWORD)
                })
}, replaceIfExists = true, baseDir = "target/certs")
class TrustedProxyTruststoreOnlyTest {

    static final String CERT_NAME = "proxy-ts-only-test";
    private static final String CERTS_DIR = "target/certs/";

    private static final String configuration = """
            quarkus.tls.key-store.p12.path=%1$s-keystore.p12
            quarkus.tls.key-store.p12.password=%2$s
            quarkus.tls.trust-store.p12.path=%1$s-server-truststore.p12
            quarkus.tls.trust-store.p12.password=%2$s
            quarkus.tls.key-store.p12.alias=%3$s
            quarkus.tls.key-store.p12.alias-password=%2$s
            quarkus.http.ssl.client-auth=REQUEST
            quarkus.http.proxy.proxy-address-forwarding=true
            quarkus.http.proxy.allow-forwarded=true
            quarkus.http.proxy.enable-trusted-proxy-header=true
            quarkus.http.proxy.trusted-proxy[0].truststore-alias=proxy
            """.formatted(CERTS_DIR + CERT_NAME, PASSWORD, CERT_NAME);

    @TestHTTPResource(value = "/trusted-proxy", tls = true)
    URL tlsUrl;

    @TestHTTPResource(value = "/trusted-proxy")
    URL httpUrl;

    @Inject
    Vertx vertx;

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(ForwardedHandlerInitializer.class)
                    .addAsResource(new StringAsset(configuration), "application.properties")
                    .addAsResource(new File(CERTS_DIR + CERT_NAME + "-keystore.p12"), "server-keystore.p12")
                    .addAsResource(new File(CERTS_DIR + CERT_NAME + "-server-truststore.p12"),
                            "server-truststore.p12"));

    @Test
    void proxyAliasClientForwardedHeadersHonored() {
        String body = requestWithClientAlias("proxy");
        assertThat(body).isEqualTo("https|somehost|backend:4444|true");
    }

    @Test
    void nonProxyAliasClientForwardedHeadersIgnored() {
        String body = requestWithClientAlias(CERT_NAME);
        assertThat(body).startsWith("https|localhost").endsWith("|false");
    }

    @Test
    void httpsWithoutClientCertForwardedHeadersIgnored() {
        RestAssured.given()
                .trustStore(CERTS_DIR + CERT_NAME + "-client-truststore.p12", PASSWORD)
                .header("Forwarded", "proto=https;for=backend:4444;host=somehost")
                .get(tlsUrl)
                .then()
                .statusCode(200)
                .body(Matchers.startsWith("https|localhost"))
                .body(Matchers.endsWith("|false"));
    }

    @Test
    void httpConnectionForwardedHeadersIgnored() {
        RestAssured.given()
                .header("Forwarded", "proto=https;for=backend:4444;host=somehost")
                .get(httpUrl)
                .then()
                .statusCode(200)
                .body(Matchers.startsWith("http|localhost"))
                .body(Matchers.endsWith("|false"));
    }

    private String requestWithClientAlias(String alias) {
        var options = new HttpClientOptions()
                .setSsl(true)
                .setDefaultPort(tlsUrl.getPort())
                .setDefaultHost(tlsUrl.getHost())
                .setKeyCertOptions(
                        new PfxOptions()
                                .setPath(CERTS_DIR + CERT_NAME + "-client-keystore.p12")
                                .setPassword(PASSWORD)
                                .setAlias(alias))
                .setTrustOptions(
                        new PfxOptions()
                                .setPath(CERTS_DIR + CERT_NAME + "-client-truststore.p12")
                                .setPassword(PASSWORD));

        var client = vertx.createHttpClient(options);
        try {
            return client
                    .request(HttpMethod.GET, "/trusted-proxy")
                    .map(req -> req.putHeader("Forwarded", "proto=https;for=backend:4444;host=somehost"))
                    .flatMap(HttpClientRequest::send)
                    .flatMap(HttpClientResponse::body)
                    .map(Buffer::toString)
                    .toCompletionStage().toCompletableFuture().join();
        } finally {
            client.close().toCompletionStage().toCompletableFuture().join();
        }
    }
}
