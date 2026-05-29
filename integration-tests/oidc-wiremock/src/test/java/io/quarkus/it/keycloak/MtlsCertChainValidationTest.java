package io.quarkus.it.keycloak;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.smallrye.certs.chain.CertificateChainGenerator;
import io.vertx.core.Vertx;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

public class MtlsCertChainValidationTest {

    private static final String CHAIN_DIR = "target/chain";
    private static final String KEY = CHAIN_DIR + "/www.quarkustest.com.key";
    private static final String LEAF_CHAIN_CERT = CHAIN_DIR + "/www.quarkustest.com.crt";
    private static final String ROOT_CERT = CHAIN_DIR + "/root.crt";
    private static final String INTERMEDIATE_CERT = CHAIN_DIR + "/intermediate.crt";
    private static final String LEAF_ONLY_CERT = CHAIN_DIR + "/www.quarkustest.com-leaf-only.crt";

    private static final int PORT = 8553;
    private static Vertx vertx;
    private HttpServer server;

    @BeforeAll
    static void generateCertificates() throws Exception {
        new CertificateChainGenerator(new File(CHAIN_DIR))
                .withCN("www.quarkustest.com")
                .generate();

        String combined = Files.readString(Path.of(LEAF_CHAIN_CERT));
        int endIdx = combined.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length();
        Files.writeString(Path.of(LEAF_ONLY_CERT), combined.substring(0, endIdx) + "\n");

        vertx = Vertx.vertx();
    }

    @AfterEach
    void cleanup() {
        if (server != null) {
            server.close().toCompletionStage().toCompletableFuture().join();
        }
    }

    @Test
    void serverTrustsRoot_clientSendsLeafAndIntermediate() throws Exception {
        startServer(new PemTrustOptions().addCertPath(ROOT_CERT));
        WebClient client = createClient(LEAF_CHAIN_CERT);
        assertSuccessfulRequest(client);
    }

    @Test
    void serverTrustsRoot_clientSendsLeafOnly() throws Exception {
        startServer(new PemTrustOptions().addCertPath(ROOT_CERT));
        WebClient client = createClient(LEAF_ONLY_CERT);
        assertFailedRequest(client);
    }

    @Test
    void serverTrustsRootAndIntermediate_clientSendsLeafOnly() throws Exception {
        startServer(new PemTrustOptions()
                .addCertPath(ROOT_CERT)
                .addCertPath(INTERMEDIATE_CERT));
        WebClient client = createClient(LEAF_ONLY_CERT);
        assertSuccessfulRequest(client);
    }

    @Test
    void serverTrustsLeaf_clientSendsLeaf() throws Exception {
        startServer(new PemTrustOptions().addCertValue(
                io.vertx.core.buffer.Buffer.buffer(Files.readString(Path.of(LEAF_ONLY_CERT)))));
        WebClient client = createClient(LEAF_ONLY_CERT);
        // the leaf is signed by the intermediate, so even if the leaf is in the truststore, that is not enough
        assertFailedRequest(client);
    }

    private void startServer(PemTrustOptions trustOptions) {
        server = vertx.createHttpServer(new HttpServerOptions()
                .setSsl(true)
                .setClientAuth(ClientAuth.REQUIRED)
                .setKeyCertOptions(new PemKeyCertOptions()
                        .setKeyPath(KEY)
                        .setCertPath(LEAF_CHAIN_CERT))
                .setTrustOptions(trustOptions))
                .requestHandler(rc -> rc.response().end("mTLS OK"))
                .listen(PORT).toCompletionStage().toCompletableFuture().join();
    }

    private WebClient createClient(String certPath) {
        return WebClient.create(vertx, new WebClientOptions()
                .setSsl(true)
                .setTrustAll(true)
                .setVerifyHost(false)
                .setKeyCertOptions(new PemKeyCertOptions()
                        .setKeyPath(KEY)
                        .setCertPath(certPath)));
    }

    private void assertSuccessfulRequest(WebClient client) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        client.get(PORT, "localhost", "/").send(ar -> {
            assertThat(ar.succeeded()).isTrue();
            assertThat(ar.result().bodyAsString()).isEqualTo("mTLS OK");
            latch.countDown();
        });
        assertThat(latch.await(10, TimeUnit.SECONDS)).isTrue();
    }

    private void assertFailedRequest(WebClient client) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        client.get(PORT, "localhost", "/").send(ar -> {
            assertThat(ar.failed()).isTrue();
            latch.countDown();
        });
        assertThat(latch.await(10, TimeUnit.SECONDS)).isTrue();
    }
}
