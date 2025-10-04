package io.quarkus.oidc.client.reactive.filter;

import java.time.Duration;
import java.util.Optional;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.hamcrest.Matchers;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.quarkus.oidc.client.reactive.filter.runtime.AbstractOidcClientRequestReactiveFilter;
import io.quarkus.rest.client.reactive.ClientExceptionMapper;
import io.quarkus.test.QuarkusDevModeTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.keycloak.server.KeycloakTestResourceLifecycleManager;
import io.restassured.RestAssured;
import io.smallrye.mutiny.Uni;

@QuarkusTestResource(KeycloakTestResourceLifecycleManager.class)
public class OidcClientFilterRevokedAccessTokenDevModeTest extends AbstractRevokedAccessTokenDevModeTest {

    private static final String MY_REACTIVE_CLIENT_RESOURCE_PATH = "/my-reactive-client-resource";

    @RegisterExtension
    static final QuarkusDevModeTest test = createQuarkusDevModeTest(
            "quarkus.rest-client-oidc-filter.refresh-on-unauthorized=true" + System.lineSeparator()
                    + MyReactiveClient.class.getName() + "/mp-rest/url=http://localhost:${quarkus.http.port}"
                    + System.lineSeparator(),
            MyDefaultClient.class, MyNamedClient.class, MyNamedClientWithoutRefresh.class, MyDefaultClientWithoutRefresh.class,
            MyClientResourceImpl.class, NamedClientRefreshDisabled.class, DefaultClientRefreshDisabled.class,
            MyReactiveClientResource.class, MyReactiveClient.class);

    @Test
    void verifyReactiveClientHasTokenRefreshedOn401() {
        RestAssured.given()
                .body(MyClientCategory.DEFAULT_CLIENT)
                .post(MY_REACTIVE_CLIENT_RESOURCE_PATH)
                .then().statusCode(200)
                .body(Matchers.is(RESPONSE));
        // access token is revoked now
        RestAssured.given()
                .body(MyClientCategory.DEFAULT_CLIENT)
                .post(MY_REACTIVE_CLIENT_RESOURCE_PATH)
                .then().statusCode(401);
        // response filter recognized 401 and told the request token to refresh the token on next request
        RestAssured.given()
                .body(MyClientCategory.DEFAULT_CLIENT)
                .post(MY_REACTIVE_CLIENT_RESOURCE_PATH)
                .then().statusCode(200)
                .body(Matchers.is(RESPONSE));
    }

    @Test
    void verifyReactiveClientWithRetryRefreshesOn401() {
        RestAssured.given()
                .body(MyClientCategory.DEFAULT_CLIENT)
                .post(MY_REACTIVE_CLIENT_RESOURCE_PATH + "/retry")
                .then().statusCode(200)
                .body(Matchers.is(RESPONSE));
        RestAssured.given()
                .body(MyClientCategory.DEFAULT_CLIENT)
                .post(MY_REACTIVE_CLIENT_RESOURCE_PATH + "/retry")
                .then().statusCode(200)
                .body(Matchers.is(RESPONSE));
    }

    @RegisterRestClient
    @OidcClientFilter
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyDefaultClient extends MyClient {

    }

    @RegisterRestClient
    @OidcClientFilter(NAMED_CLIENT)
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyNamedClient extends MyClient {

    }

    @RegisterRestClient
    @RegisterProvider(value = DefaultClientRefreshDisabled.class)
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyDefaultClientWithoutRefresh extends MyClient {

    }

    @Priority(Priorities.AUTHENTICATION)
    public static class DefaultClientRefreshDisabled extends AbstractOidcClientRequestReactiveFilter {
    }

    @RegisterRestClient
    @RegisterProvider(value = NamedClientRefreshDisabled.class)
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyNamedClientWithoutRefresh extends MyClient {

    }

    @Priority(Priorities.AUTHENTICATION)
    public static class NamedClientRefreshDisabled extends AbstractOidcClientRequestReactiveFilter {
        @Override
        protected Optional<String> clientId() {
            return Optional.of(NAMED_CLIENT);
        }
    }

    @Path(MY_CLIENT_RESOURCE_PATH)
    public static class MyClientResourceImpl extends MyClientResource {

        @Inject
        @RestClient
        MyDefaultClient myDefaultClient;

        @Inject
        @RestClient
        MyNamedClient myNamedClient;

        @Inject
        @RestClient
        MyDefaultClientWithoutRefresh myDefaultClientWithoutRefresh;

        @Inject
        @RestClient
        MyNamedClientWithoutRefresh myNamedClientWithoutRefresh;

        @Override
        protected MyClient myDefaultClient() {
            return myDefaultClient;
        }

        @Override
        protected MyClient myNamedClient() {
            return myNamedClient;
        }

        @Override
        protected MyClient myDefaultClientWithoutRefresh() {
            return myDefaultClientWithoutRefresh;
        }

        @Override
        protected MyClient myNamedClientWithoutRefresh() {
            return myNamedClientWithoutRefresh;
        }
    }

    @RegisterRestClient
    @OidcClientFilter
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyReactiveClient {

        @POST
        Uni<String> revokeAccessTokenAndRespond(String named);

        @ClientExceptionMapper
        static RuntimeException toException(Response response) {
            if (response.getStatus() == 401) {
                return new IllegalArgumentException("I hate 401!");
            }
            return null;
        }
    }

    @Path(MY_REACTIVE_CLIENT_RESOURCE_PATH)
    public static class MyReactiveClientResource {

        @Inject
        @RestClient
        MyReactiveClient client;

        @POST
        public Uni<String> talkToServerAndRespond(MyClientCategory clientCategory) {
            return client.revokeAccessTokenAndRespond(clientCategory.named + "");
        }

        @Path("/retry")
        @POST
        public Uni<String> talkToServerAndRespondWithRetry(MyClientCategory clientCategory) {
            return client.revokeAccessTokenAndRespond(clientCategory.named + "")
                    .onFailure().invoke(failure -> System.out.println("/////////// encountered failure " + failure))
                    .onFailure(IllegalArgumentException.class)
                    .retry()
                    .withBackOff(Duration.ofMillis(300), Duration.ofMillis(300))
                    .atMost(1);
        }

        @ServerExceptionMapper(value = WebApplicationException.class)
        public RestResponse<Response> mapExceptions(WebApplicationException exception) {
            return RestResponse.status(exception.getResponse().getStatus());
        }

    }
}
