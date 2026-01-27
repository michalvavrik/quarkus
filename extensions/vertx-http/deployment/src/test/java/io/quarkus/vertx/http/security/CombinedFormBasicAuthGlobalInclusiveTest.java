package io.quarkus.vertx.http.security;

import java.util.Map;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class CombinedFormBasicAuthGlobalInclusiveTest extends AbstractCombinedFormBasicAuthInclusiveAuthTest {

    @RegisterExtension
    static final QuarkusUnitTest test = createTestApp(Map.of("quarkus.http.auth.inclusive", "true"));

}
