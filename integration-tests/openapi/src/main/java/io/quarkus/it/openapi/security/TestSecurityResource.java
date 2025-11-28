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
    public static final String TEST_HEADER_VALUE = "hush-hush";
    public static int REQUEST_TIMEOUT = 3;

    @Inject
    ExceptionStorage exceptionStorage;

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
        try {
            // ATM this code is not invoked every single time, it is timing issue
            // but on my laptop it is invoked 7 times out of 10, therefore, if re-run multiple times,
            // it sufficiently reproduces our original issue with accessing CDI request context
            var headerValue = httpHeaders.getHeaderString(TEST_HEADER_NAME);

            // just to do something - check the expected value
            if (!TEST_HEADER_VALUE.equals(headerValue)) {
                throw new IllegalStateException(
                        "Invalid header value, got '%s',but expected '%s' ".formatted(headerValue, TEST_HEADER_VALUE));
            }
        } catch (Exception e) {
            exceptionStorage.setException(e);
        }
        return securityContext.getUserPrincipal().getName();
    }

    @Path("exception")
    @GET
    public String getRaisedException() {
        return String.valueOf(exceptionStorage.getException());
    }

    @RouteFilter(401)
    public void doNothing(RoutingContext routingContext) {
        // here so that the Reactive Routes extension activates CDI request context
        routingContext.response().putHeader("reactive-routes-filter", "true");
        routingContext.next();
    }

}
