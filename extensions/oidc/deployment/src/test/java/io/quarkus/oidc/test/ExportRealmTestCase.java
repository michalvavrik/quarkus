package io.quarkus.oidc.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.deployment.util.FileUtil;
import io.quarkus.test.QuarkusDevModeTest;

public class ExportRealmTestCase {

    private static final String APPLICATION_PROPERTIES = "application.properties";
    private static final String REALM_FILE_NAME = "realm.json";
    private static Path realmDir;

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot(new Consumer<JavaArchive>() {
                @Override
                public void accept(JavaArchive jar) {
                    try {
                        realmDir = Files.createTempDirectory("quarkus-dev-mode-export-realm-test-dir");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    jar
                            .addAsResource(new StringAsset(String.format("quarkus.keycloak.devservices.export-realm-path=%s",
                                    realmDir.toAbsolutePath())), APPLICATION_PROPERTIES);
                }
            });

    @AfterAll
    public static void assertResult() throws IOException {
        try {
            final var realmFilePath = realmDir.resolve(REALM_FILE_NAME);
            Assertions.assertTrue(Files.exists(realmFilePath));
            final var realmAsStr = Files.readString(realmFilePath);
            Assertions.assertTrue(realmAsStr.contains("master-realm"));
        } finally {
            FileUtil.deleteDirectory(realmDir);
        }
    }

    @Test
    public void test() {
        // result is asserted after application is stopped as that's when container is stopped and realm exported
    }

}
