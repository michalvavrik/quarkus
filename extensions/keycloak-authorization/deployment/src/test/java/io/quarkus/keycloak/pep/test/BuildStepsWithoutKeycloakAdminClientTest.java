package io.quarkus.keycloak.pep.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;

import io.quarkus.bootstrap.classloading.ClassPathElement;
import io.quarkus.bootstrap.classloading.QuarkusClassLoader;
import io.quarkus.keycloak.admin.client.common.deployment.KeycloakAdminClientProcessor;
import io.quarkus.keycloak.admin.client.common.runtime.KeycloakAdminClientJsonMapper;
import io.quarkus.keycloak.pep.deployment.KeycloakAdminClientSupportProcessor;

/**
 * The Keycloak admin client extensions are optional dependencies of this extension and most applications use this
 * extension without them. This test makes sure that Quarkus can load the build steps of this extension in such
 * applications.
 * <p>
 * The Keycloak admin client is always on the class path of this module and a {@code QuarkusExtensionTest} loads the build
 * steps from that class path even when dependencies are excluded, so the build steps are loaded by a class loader which
 * bans the Keycloak admin client here.
 */
public class BuildStepsWithoutKeycloakAdminClientTest {

    private static final String BUILD_STEPS_LIST = "META-INF/quarkus-build-steps.list";

    @Test
    public void testBuildStepsAreLoaded() throws Exception {
        ClassPathElement buildSteps = ClassPathElement.fromPath(location(KeycloakAdminClientSupportProcessor.class), false);
        List<String> buildStepClasses = new String(buildSteps.getResource(BUILD_STEPS_LIST).getData(),
                StandardCharsets.UTF_8).lines().filter(line -> !line.isBlank()).toList();
        assertThat(buildStepClasses).contains(KeycloakAdminClientSupportProcessor.class.getName());

        try (QuarkusClassLoader classLoader = QuarkusClassLoader
                .builder("Keycloak Authorization without the Keycloak admin client", getClass().getClassLoader(), false)
                .addNormalPriorityElement(buildSteps)
                .addBannedElement(ClassPathElement.fromPath(location(KeycloakAdminClientProcessor.class), false))
                .addBannedElement(ClassPathElement.fromPath(location(KeycloakAdminClientJsonMapper.class), false))
                .addBannedElement(ClassPathElement.fromPath(location(Keycloak.class), false))
                .build()) {
            assertThatThrownBy(() -> classLoader.loadClass(KeycloakAdminClientJsonMapper.class.getName()))
                    .isInstanceOf(ClassNotFoundException.class);

            for (String buildStepClass : buildStepClasses) {
                // the build step class must be defined by the class loader, so that the class loader resolves its references
                Class<?> clazz = Class.forName(buildStepClass, true, classLoader);
                assertThat(clazz.getClassLoader()).isSameAs(classLoader);
                assertThatCode(() -> {
                    // this is what the io.quarkus.deployment.ExtensionLoader does with every build step class,
                    // no matter if the conditions of its build steps are met
                    clazz.getDeclaredConstructors();
                    clazz.getDeclaredFields();
                    clazz.getDeclaredMethods();
                }).as("Build steps of %s must be loaded when the Keycloak admin client is absent", buildStepClass)
                        .doesNotThrowAnyException();
            }
        }
    }

    private static Path location(Class<?> clazz) throws Exception {
        return Path.of(clazz.getProtectionDomain().getCodeSource().getLocation().toURI());
    }
}
