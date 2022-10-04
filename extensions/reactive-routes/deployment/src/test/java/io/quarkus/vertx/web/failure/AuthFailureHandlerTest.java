package io.quarkus.vertx.web.failure;

import static io.quarkus.vertx.web.Route.HandlerType.FAILURE;
import static io.restassured.RestAssured.get;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.function.Supplier;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.Authenticated;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.web.Param;
import io.quarkus.vertx.web.Route;
import io.vertx.core.http.HttpServerResponse;

public class AuthFailureHandlerTest {

    private static final String EXPECTED_BODY = "Authentication failed";
    private static final String USER_DEFINED_HANDLER_PATH = "/user-defined-handler";
    private static final String DEFAULT_HANDLER_PATH = "/default-handler";

    @RegisterExtension
    static QuarkusUnitTest test = new QuarkusUnitTest().setArchiveProducer(new Supplier<>() {
        @Override
        public JavaArchive get() {
            return ShrinkWrap.create(JavaArchive.class)
                    .addClasses(TestIdentityProvider.class, Routes.class, FailingAuthMechanism.class)
                    .addAsResource(new StringAsset("quarkus.http.auth.form.enabled=true\n"), "application.properties");
        }
    });

    @Test
    public void testUserDefinedFailureHandler() {
        get(USER_DEFINED_HANDLER_PATH).then().statusCode(401).body(is(EXPECTED_BODY));
    }

    @Test
    public void testDefaultFailureHandler() {
        get(DEFAULT_HANDLER_PATH).then().statusCode(401).body(not(EXPECTED_BODY));
    }

    public static class Routes {

        @Authenticated
        @Route(path = USER_DEFINED_HANDLER_PATH)
        String userDefinedHandler(@Param String type) {
            return "ignored";
        }

        @Authenticated
        @Route(path = DEFAULT_HANDLER_PATH)
        String defaultHandler(@Param String type) {
            return "ignored";
        }

        @Route(path = USER_DEFINED_HANDLER_PATH, type = FAILURE, order = 1)
        void authFailureHandler(AuthenticationFailedException e, HttpServerResponse response) {
            response.setStatusCode(401).end(EXPECTED_BODY);
        }

    }

}
