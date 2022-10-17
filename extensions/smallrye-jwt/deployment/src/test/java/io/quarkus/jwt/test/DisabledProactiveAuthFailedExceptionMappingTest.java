package io.quarkus.jwt.test;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class DisabledProactiveAuthFailedExceptionMappingTest extends AbstractAuthFailedExceptionMappingTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(classes)
                    .addAsResource(new StringAsset("quarkus.http.auth.proactive=false\n"), "application.properties"));

}
