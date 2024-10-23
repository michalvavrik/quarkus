package io.quarkus.it.keycloak;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.SecurityContext;

import io.quarkus.security.Authenticated;

@Path("/code-flow-slack")
public class SlackCodeFlowResource {

    @Authenticated
    @GET
    public String getSecurityIdentityPrincipal(SecurityContext securityContext) {
        return securityContext.getUserPrincipal().getName();
    }

}
