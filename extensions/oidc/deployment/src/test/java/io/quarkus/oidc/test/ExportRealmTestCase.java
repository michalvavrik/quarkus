package io.quarkus.oidc.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.deployment.util.FileUtil;
import io.quarkus.test.QuarkusDevModeTest;

public class ExportRealmTestCase {

    private static Class<?>[] testClasses = {
            UnprotectedResource.class
    };
    private static final String APPLICATION_PROPERTIES = "application.properties";
    private static final String REALM_FILE_NAME = "realm.json";
    private Path realmDir;

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(testClasses)
                    .addAsResource(new StringAsset("quarkus.keycloak.devservices.enabled=true"), APPLICATION_PROPERTIES));

    @BeforeEach
    public void createRealmDir() throws IOException {
        realmDir = Files.createTempDirectory("quarkus-dev-mode-export-realm-test-dir");
    }

    @AfterEach
    public void deleteRealmDir() throws IOException {
        FileUtil.deleteDirectory(realmDir);
    }

    @Test
    public void test() {
        // we start without realm export path set, therefore we know it's optional
        final var realmFilePath = realmDir.resolve(REALM_FILE_NAME);
        Assertions.assertFalse(Files.exists(realmFilePath));
        // set export dir
        test.modifyResourceFile(APPLICATION_PROPERTIES,
                fileAsStr -> String.format("quarkus.keycloak.devservices.export-realm-path=%s", realmDir.toAbsolutePath()));
        // stop Keycloak container
        test.modifyResourceFile(APPLICATION_PROPERTIES,
                fileAsStr -> fileAsStr.replace("=true", "=false"));
        // validate exported file
        Assertions.assertTrue(Files.exists(realmFilePath));
    }

}
