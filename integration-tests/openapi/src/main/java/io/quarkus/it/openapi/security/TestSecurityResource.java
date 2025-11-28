package io.quarkus.it.openapi.security;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.SecurityContext;

import io.quarkus.vertx.web.RouteFilter;
import io.vertx.ext.web.RoutingContext;

@Path("/security")
public class TestSecurityResource {

    public static final String TEST_HEADER_NAME = "test-security-header";
    public static int REQUEST_TIMEOUT = 3;

    @Inject
    TestHeaderStorage testHeaderStorage;

    @Context
    HttpHeaders httpHeaders;

    @RolesAllowed("admin")
    @GET
    @Path("reactive-routes")
    public String reactiveRoutes(@Context SecurityContext securityContext) {
        return securityContext.getUserPrincipal().getName();
    }

    @RolesAllowed("admin")
    @GET
    @Path("reactive-routes-with-delayed-response")
    public String reactiveRoutesWithDelayedResponse(@Context SecurityContext securityContext) throws InterruptedException {
        Thread.sleep(REQUEST_TIMEOUT);
        testHeaderStorage.setHeaderValue(httpHeaders.getHeaderString(TEST_HEADER_NAME));
        return securityContext.getUserPrincipal().getName();
    }

    @Path("test-header")
    @GET
    public String getTestHeader() {
        return TEST_HEADER_NAME + " header value was: " + testHeaderStorage.getHeaderValue();
    }

    @RouteFilter(401)
    public void doNothing(RoutingContext routingContext) {
        // here so that the Reactive Routes extension activates CDI request context
        routingContext.response().putHeader("reactive-routes-filter", "true");
        routingContext.next();
    }

}
