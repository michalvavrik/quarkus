package io.quarkus.vertx.http.tls;

import java.io.File;
import java.net.URL;
import java.security.cert.X509Certificate;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.smallrye.certs.Format;
import io.smallrye.certs.junit5.Alias;
import io.smallrye.certs.junit5.Certificate;
import io.smallrye.certs.junit5.Certificates;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

@Certificates(baseDir = "target/certs", certificates = @Certificate(name = "ssl-test-sni-alias", password = "secret", formats = {
        Format.PKCS12 }, aliases = {
                @Alias(name = "sni-1", password = "secret", cn = "acme.org", subjectAlternativeNames = "DNS:acme.org"),
                @Alias(name = "sni-2", password = "secret", cn = "example.com", subjectAlternativeNames = "DNS:example.com"),
        }))
public class TlsServerWithSniAndExplicitAliasTest {

    @TestHTTPResource(value = "/tls", tls = true)
    URL url;

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(MyBean.class)
                    .addAsResource(new File("target/certs/ssl-test-sni-alias-keystore.p12"), "server-keystore.pkcs12"))
            .overrideConfigKey("quarkus.tls.key-store.p12.path", "server-keystore.pkcs12")
            .overrideConfigKey("quarkus.tls.key-store.p12.password", "secret")
            .overrideConfigKey("quarkus.tls.key-store.p12.alias-password", "secret")
            .overrideConfigKey("quarkus.tls.key-store.p12.alias", "sni-1")
            .overrideConfigKey("quarkus.tls.key-store.sni", "true");

    @Inject
    Vertx vertx;

    @Test
    public void testSniWithExplicitAlias() {
        WebClientOptions options = new WebClientOptions()
                .setSsl(true)
                .setTrustAll(true)
                .setVerifyHost(false)
                .setForceSni(true);
        WebClient client = WebClient.create(vertx, options);
        HttpResponse<Buffer> response = client.getAbs(url.toExternalForm()).send().toCompletionStage()
                .toCompletableFuture().join();
        Assertions.assertThat(response.statusCode()).isEqualTo(200);
        String[] parts = response.bodyAsString().split("\\|");
        Assertions.assertThat(parts[0]).isEqualTo("localhost");
        Assertions.assertThat(parts[1]).contains("acme.org");
    }

    @ApplicationScoped
    static class MyBean {

        public void register(@Observes Router router) {
            router.get("/tls").handler(rc -> {
                Assertions.assertThat(rc.request().connection().isSsl()).isTrue();
                Assertions.assertThat(rc.request().isSSL()).isTrue();
                Assertions.assertThat(rc.request().connection().sslSession()).isNotNull();

                String indicatedServerName = rc.request().connection().indicatedServerName();
                String certCn;
                try {
                    X509Certificate certificate = (X509Certificate) rc.request().connection().sslSession()
                            .getLocalCertificates()[0];
                    certCn = certificate.getSubjectX500Principal().getName();
                } catch (Exception e) {
                    certCn = "ERROR";
                }
                rc.response().end(indicatedServerName + "|" + certCn);
            });
        }
    }
}
