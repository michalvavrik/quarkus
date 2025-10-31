package io.quarkus.oidc.client.filter;

import java.util.Optional;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Priorities;

import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.client.filter.runtime.AbstractOidcClientRequestFilter;
import io.quarkus.test.QuarkusDevModeTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.keycloak.server.KeycloakTestResourceLifecycleManager;

@QuarkusTestResource(KeycloakTestResourceLifecycleManager.class)
public class OidcClientFilterRevokedAccessTokenDevModeTest extends AbstractRevokedAccessTokenDevModeTest {

    @RegisterExtension
    static final QuarkusDevModeTest test = createQuarkusDevModeTest("""
            quarkus.resteasy-client-oidc-filter.refresh-on-unauthorized=true
            %s/mp-rest/url=http://localhost:${quarkus.http.port}
            %s/mp-rest/url=http://localhost:${quarkus.http.port}
            """.formatted(MyDefaultClient_AnnotationOnMethod.class.getName(), MyNamedClient_AnnotationOnMethod.class.getName()),
            MyDefaultClient.class, MyNamedClient.class,
            MyNamedClientWithoutRefresh.class, MyDefaultClientWithoutRefresh.class, MyClientResourceImpl.class,
            DefaultClientRefreshDisabled.class, NamedClientRefreshDisabled.class, MyDefaultClient_AnnotationOnMethod.class,
            MyNamedClient_AnnotationOnMethod.class);

    @Test
    void verifyNamedClientHasTokenRefreshedOn401() {
        verifyNamedClientHasTokenRefreshedOn401(MyClientCategory.NAMED_CLIENT);
        verifyNamedClientHasTokenRefreshedOn401(MyClientCategory.NAMED_CLIENT_ANNOTATION_ON_METHOD);
    }

    @Test
    void verifyDefaultClientHasTokenRefreshedOn401() {
        verifyDefaultClientHasTokenRefreshedOn401(MyClientCategory.DEFAULT_CLIENT);
        verifyDefaultClientHasTokenRefreshedOn401(MyClientCategory.DEFAULT_CLIENT_ANNOTATION_ON_METHOD);
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
    public static class DefaultClientRefreshDisabled extends AbstractOidcClientRequestFilter {
    }

    @RegisterRestClient
    @RegisterProvider(value = NamedClientRefreshDisabled.class)
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyNamedClientWithoutRefresh extends MyClient {

    }

    @Priority(Priorities.AUTHENTICATION)
    public static class NamedClientRefreshDisabled extends AbstractOidcClientRequestFilter {
        @Override
        protected Optional<String> clientId() {
            return Optional.of(NAMED_CLIENT);
        }
    }

    @RegisterRestClient
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyDefaultClient_AnnotationOnMethod {
        @OidcClientFilter
        @POST
        String revokeAccessTokenAndRespond(String named);
    }

    @RegisterRestClient
    @Path(MY_SERVER_RESOURCE_PATH)
    public interface MyNamedClient_AnnotationOnMethod {
        @OidcClientFilter(NAMED_CLIENT)
        @POST
        String revokeAccessTokenAndRespond(String named);
    }

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

        @Inject
        @RestClient
        MyDefaultClient_AnnotationOnMethod myDefaultClientAnnotationOnMethod;

        @Inject
        @RestClient
        MyNamedClient_AnnotationOnMethod myNamedClientAnnotationOnMethod;

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

        @Override
        protected String myDefaultClient_AnnotationOnMethod(String named) {
            return myDefaultClientAnnotationOnMethod.revokeAccessTokenAndRespond(named);
        }

        @Override
        protected String myNamedClient_AnnotationOnMethod(String named) {
            return myNamedClientAnnotationOnMethod.revokeAccessTokenAndRespond(named);
        }
    }

}
