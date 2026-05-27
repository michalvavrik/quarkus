package io.quarkus.vertx.http.proxy;

import static io.quarkus.vertx.http.proxy.AbstractTrustedProxyDnTest.PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import jakarta.inject.Inject;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.ForwardedHandlerInitializer;
import io.restassured.RestAssured;
import io.smallrye.certs.chain.CertificateChainGenerator;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.PfxOptions;

class TrustedProxyDnWithTruststoreTest {

    private static final String CERTS_DIR = "target/proxy-dn-ts-test/";
    private static final File BASE_DIR = new File(CERTS_DIR);
    private static final File CHAIN1_DIR = new File(BASE_DIR, "chain1");
    private static final File CHAIN2_DIR = new File(BASE_DIR, "chain2");
    private static final File SERVER_KEYSTORE = new File(BASE_DIR, "server-keystore.p12");
    private static final File SERVER_TRUSTSTORE = new File(BASE_DIR, "server-truststore.p12");
    private static final File CLIENT1_KEYSTORE = new File(BASE_DIR, "client1-keystore.p12");
    private static final File CLIENT2_KEYSTORE = new File(BASE_DIR, "client2-keystore.p12");
    private static final File CLIENT_TRUSTSTORE = new File(BASE_DIR, "client-truststore.p12");
    private static final String TRUSTED_CA = "trusted-ca";

    private static final String configuration = """
            quarkus.tls.http-server.key-store.p12.path=%1$sserver-keystore.p12
            quarkus.tls.http-server.key-store.p12.password=%2$s
            quarkus.tls.http-server.trust-store.p12.path=%1$sserver-truststore.p12
            quarkus.tls.http-server.trust-store.p12.password=%2$s
            quarkus.http.tls-configuration-name=http-server
            quarkus.http.ssl.client-auth=REQUEST
            quarkus.http.proxy.proxy-address-forwarding=true
            quarkus.http.proxy.allow-forwarded=true
            quarkus.http.proxy.enable-trusted-proxy-header=true
            quarkus.http.proxy.trusted-proxy[0].subject-dn=CN=proxy
            quarkus.http.proxy.trusted-proxy[0].truststore-alias=%3$s
            """.formatted(CERTS_DIR, PASSWORD, TRUSTED_CA);

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
                    .addAsResource(new StringAsset(configuration), "application.properties"))
            .setBeforeAllCustomizer(TrustedProxyDnWithTruststoreTest::generateCertificates);

    @Test
    void trustedProxyForwardedHeadersHonored() {
        String body = requestWithClientKeystore(CLIENT1_KEYSTORE);
        assertThat(body).isEqualTo("https|somehost|backend:4444|true");
    }

    @Test
    void impostorWithSameDnButWrongCaForwardedHeadersIgnored() {
        String body = requestWithClientKeystore(CLIENT2_KEYSTORE);
        assertThat(body).startsWith("https|localhost").endsWith("|false");
    }

    @Test
    void httpsWithoutClientCertForwardedHeadersIgnored() {
        RestAssured.given()
                .trustStore(CLIENT_TRUSTSTORE.getPath(), PASSWORD)
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

    /**
     * Here we generate a truststore with 2 different root CAs and leaf certificates which share same subject DN.
     */
    private static void generateCertificates() {
        try {
            deleteDir(BASE_DIR);
            CHAIN1_DIR.mkdirs();
            CHAIN2_DIR.mkdirs();
            char[] pass = PASSWORD.toCharArray();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            new CertificateChainGenerator(CHAIN1_DIR).withCN("proxy").withSAN(List.of("DNS:localhost")).generate();
            new CertificateChainGenerator(CHAIN2_DIR).withCN("proxy").withSAN(List.of("DNS:localhost")).generate();

            X509Certificate root1 = loadCert(cf, new File(CHAIN1_DIR, "root.crt"));
            X509Certificate inter1 = loadCert(cf, new File(CHAIN1_DIR, "intermediate.crt"));
            X509Certificate leaf1 = loadCert(cf, new File(CHAIN1_DIR, "proxy.crt"));
            PrivateKey leafKey1 = loadPkcs8Key(new File(CHAIN1_DIR, "proxy.key"));

            X509Certificate root2 = loadCert(cf, new File(CHAIN2_DIR, "root.crt"));
            X509Certificate inter2 = loadCert(cf, new File(CHAIN2_DIR, "intermediate.crt"));
            X509Certificate leaf2 = loadCert(cf, new File(CHAIN2_DIR, "proxy.crt"));
            PrivateKey leafKey2 = loadPkcs8Key(new File(CHAIN2_DIR, "proxy.key"));

            assertThat(leaf1.getSubjectX500Principal().getName()).contains("CN=proxy")
                    .isEqualTo(leaf2.getSubjectX500Principal().getName());
            assertThat(leaf1.getIssuerX500Principal()).isEqualTo(inter1.getSubjectX500Principal());
            assertThat(leaf2.getSubjectX500Principal().getName()).contains("CN=proxy");
            assertThat(leaf2.getIssuerX500Principal()).isEqualTo(inter2.getSubjectX500Principal());
            assertThat(root1.getPublicKey()).isNotEqualTo(root2.getPublicKey());

            buildPkcs12(SERVER_KEYSTORE, pass, ks -> ks.setKeyEntry("server", leafKey1, pass,
                    new java.security.cert.Certificate[] { leaf1, inter1, root1 }));

            buildPkcs12(SERVER_TRUSTSTORE, pass, ks -> {
                ks.setCertificateEntry(TRUSTED_CA, root1);
                ks.setCertificateEntry("impostor-ca", root2);
            });

            // Client 1 keystore is for trusted proxy
            buildPkcs12(CLIENT1_KEYSTORE, pass, ks -> ks.setKeyEntry("client", leafKey1, pass,
                    new java.security.cert.Certificate[] { leaf1, inter1, root1 }));

            // Client 2 keystore is for impostor proxy
            buildPkcs12(CLIENT2_KEYSTORE, pass, ks -> ks.setKeyEntry("client", leafKey2, pass,
                    new java.security.cert.Certificate[] { leaf2, inter2, root2 }));

            // Client truststore: clients must trust server
            buildPkcs12(CLIENT_TRUSTSTORE, pass, ks -> ks.setCertificateEntry("server-ca", root1));

            KeyStore verify = loadServerTruststore(pass);
            assertThat(Collections.list(verify.aliases())).containsExactlyInAnyOrder(TRUSTED_CA, "impostor-ca");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate loadCert(CertificateFactory cf, File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private static PrivateKey loadPkcs8Key(File file) throws Exception {
        String pem = Files.readString(file.toPath());
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static KeyStore loadServerTruststore(char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TrustedProxyDnWithTruststoreTest.SERVER_TRUSTSTORE)) {
            ks.load(fis, password);
        }
        return ks;
    }

    private static void buildPkcs12(File file, char[] password, KeyStorePopulator populator) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        populator.populate(ks);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, password);
        }
    }

    private static void deleteDir(File dir) {
        if (dir.exists()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) {
                        deleteDir(f);
                    } else {
                        f.delete();
                    }
                }
            }
            dir.delete();
        }
    }

    @FunctionalInterface
    private interface KeyStorePopulator {
        void populate(KeyStore ks) throws Exception;
    }

    private String requestWithClientKeystore(File keystoreFile) {
        var options = new HttpClientOptions()
                .setSsl(true)
                .setDefaultPort(tlsUrl.getPort())
                .setDefaultHost(tlsUrl.getHost())
                .setKeyCertOptions(
                        new PfxOptions()
                                .setPath(keystoreFile.getPath())
                                .setPassword(PASSWORD))
                .setTrustOptions(
                        new PfxOptions()
                                .setPath(CLIENT_TRUSTSTORE.getPath())
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
