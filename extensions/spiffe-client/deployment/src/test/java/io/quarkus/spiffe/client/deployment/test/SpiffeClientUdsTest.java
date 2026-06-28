package io.quarkus.spiffe.client.deployment.test;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

class SpiffeClientUdsTest extends AbstractSpiffeClientTest {

    @RegisterExtension
    static final QuarkusExtensionTest CONFIG = new QuarkusExtensionTest();
}
