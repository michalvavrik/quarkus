package io.quarkus.it.keycloak;

import java.util.List;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Path("/api/admin")
public class AdminResource {

    @Inject
    Keycloak keycloak;

    @Claim("preferred_username")
    ClaimValue<String> claim;

    @Path("/grant")
    @GET
    @RolesAllowed("admin")
    public String admin() {
        return "granted:" + claim.getValue();
    }

    @Path("/realm-users")
    @GET
    @RolesAllowed("admin")
    public List<UserRepresentation> realmUsers() {
        return keycloak.realm("quarkus").users().list();
    }
}
