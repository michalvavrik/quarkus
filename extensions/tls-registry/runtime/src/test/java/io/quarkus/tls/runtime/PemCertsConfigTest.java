package io.quarkus.tls.runtime;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.quarkus.tls.runtime.config.PemCertsConfig;

/**
 * Tests {@link io.quarkus.tls.runtime.config.PemCertsConfig} default methods.
 */
class PemCertsConfigTest {

    public static final String TEMP_CERT_PREFIX = "PemCertsConfigTest";

    private record PemCertsConfigImpl(Optional<List<Path>> certs, Optional<List<Path>> certDirs) implements PemCertsConfig {
    }

    @Test
    void testHasNoTrustedCertificates() throws IOException {
        Path emptyTempCertDir = Files.createTempDirectory(TEMP_CERT_PREFIX);
        Path tempCertDirWith1File = Files.createTempDirectory(TEMP_CERT_PREFIX);
        Path certInTempCertDirWith1File = tempCertDirWith1File.resolve("ts.pem");
        Files.createFile(certInTempCertDirWith1File);
        Path tempCertDirWith2Files = Files.createTempDirectory(TEMP_CERT_PREFIX);
        Files.createFile(tempCertDirWith2Files.resolve("ts-1.pem"));
        Files.createFile(tempCertDirWith2Files.resolve("ts-2.pem"));

        var noCertsFoundConfig = new PemCertsConfigImpl(Optional.of(List.of()), Optional.of(List.of(emptyTempCertDir)));
        assertThat(noCertsFoundConfig.hasNoTrustedCertificates()).isTrue();

        var onlyCertFileConfig = new PemCertsConfigImpl(Optional.of(List.of(certInTempCertDirWith1File)), Optional.empty());
        assertThat(onlyCertFileConfig.hasNoTrustedCertificates()).isFalse();

        var certFileAndEmptyDirConfig = new PemCertsConfigImpl(Optional.of(List.of(certInTempCertDirWith1File)),
                Optional.of(List.of(emptyTempCertDir)));
        assertThat(certFileAndEmptyDirConfig.hasNoTrustedCertificates()).isFalse();

        var certFileAndCertDirConfig = new PemCertsConfigImpl(Optional.of(List.of(certInTempCertDirWith1File)),
                Optional.of(List.of(tempCertDirWith2Files)));
        assertThat(certFileAndCertDirConfig.hasNoTrustedCertificates()).isFalse();

        var certDirConfig = new PemCertsConfigImpl(Optional.empty(), Optional.of(List.of(tempCertDirWith2Files)));
        assertThat(certDirConfig.hasNoTrustedCertificates()).isFalse();

        var multipleCertDirsConfig = new PemCertsConfigImpl(Optional.empty(),
                Optional.of(List.of(tempCertDirWith1File, tempCertDirWith2Files)));
        assertThat(multipleCertDirsConfig.hasNoTrustedCertificates()).isFalse();
    }

    @Test
    void testToOptions() {

    }

}
