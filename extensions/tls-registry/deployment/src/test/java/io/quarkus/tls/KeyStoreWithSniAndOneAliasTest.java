package io.quarkus.tls;

import static io.smallrye.certs.Format.JKS;
import static io.smallrye.certs.Format.PEM;
import static io.smallrye.certs.Format.PKCS12;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.smallrye.certs.junit5.Certificate;
import io.smallrye.certs.junit5.Certificates;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

@Certificates(baseDir = "target/certs", certificates = {
        @Certificate(name = "test-sni-single", password = "sni", formats = { PKCS12, JKS,
                PEM }, cn = "localhost", subjectAlternativeNames = "DNS:localhost")
})
public class KeyStoreWithSniAndOneAliasTest {

    private static final String configuration = """
            quarkus.tls.key-store.p12.path=target/certs/test-sni-single-keystore.p12
            quarkus.tls.key-store.p12.password=sni
            quarkus.tls.key-store.sni=true

            quarkus.tls.jks.key-store.jks.path=target/certs/test-sni-single-keystore.jks
            quarkus.tls.jks.key-store.jks.password=sni
            quarkus.tls.jks.key-store.sni=true

            quarkus.tls.pem.key-store.pem.a.cert=target/certs/test-sni-single.crt
            quarkus.tls.pem.key-store.pem.a.key=target/certs/test-sni-single.key
            quarkus.tls.pem.key-store.sni=true
            """;

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest().setArchiveProducer(
            () -> ShrinkWrap.create(JavaArchive.class)
                    .add(new StringAsset(configuration), "application.properties"));

    @Inject
    TlsConfigurationRegistry registry;

    @Inject
    Vertx vertx;

    private HttpServer server;

    @AfterEach
    void cleanup() {
        if (server != null) {
            server.close().toCompletionStage().toCompletableFuture().join();
        }
    }

    @Test
    void testP12SingleAliasWithSni() throws KeyStoreException, InterruptedException {
        TlsConfiguration tlsConfiguration = registry.getDefault().orElseThrow();
        assertThat(tlsConfiguration.usesSni()).isTrue();
        assertThat(tlsConfiguration.getKeyStore().size()).isEqualTo(1);

        server = vertx.createHttpServer(new HttpServerOptions()
                .setSsl(true)
                .setSni(true)
                .setKeyCertOptions(tlsConfiguration.getKeyStoreOptions()))
                .requestHandler(rc -> {
                    String sni = rc.connection().indicatedServerName();
                    String certCn;
                    try {
                        X509Certificate cert = (X509Certificate) rc.connection().sslSession()
                                .getLocalCertificates()[0];
                        certCn = cert.getSubjectX500Principal().getName();
                    } catch (Exception e) {
                        certCn = "ERROR";
                    }
                    rc.response().end(sni + "|" + certCn);
                })
                .listen(0).toCompletionStage().toCompletableFuture().join();

        WebClient client = WebClient.create(vertx, new WebClientOptions()
                .setSsl(true)
                .setTrustAll(true)
                .setVerifyHost(false)
                .setForceSni(true));

        int port = server.actualPort();
        CountDownLatch latch = new CountDownLatch(1);
        client.get(port, "localhost", "/").send().onComplete(ar -> {
            assertThat(ar.succeeded()).isTrue();
            String[] parts = ar.result().bodyAsString().split("\\|");
            assertThat(parts[0]).isEqualTo("localhost");
            assertThat(parts[1]).contains("localhost");
            latch.countDown();
        });

        assertThat(latch.await(10, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void testJksSingleAliasWithSni() throws KeyStoreException {
        TlsConfiguration tlsConfiguration = registry.get("jks").orElseThrow();
        assertThat(tlsConfiguration.usesSni()).isTrue();
        assertThat(tlsConfiguration.getKeyStore().size()).isEqualTo(1);
    }

    @Test
    void testPemSingleCertWithSni() throws KeyStoreException {
        TlsConfiguration tlsConfiguration = registry.get("pem").orElseThrow();
        assertThat(tlsConfiguration.usesSni()).isTrue();
        assertThat(tlsConfiguration.getKeyStore().size()).isEqualTo(1);
    }
}
