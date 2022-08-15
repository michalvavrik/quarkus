package io.quarkus.it.keycloak;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

@Path("/admin-client")
public class AdminClientResource {

    @Named("admin")
    @Inject
    Keycloak keycloakAdmin;

    @Named("service-account")
    Keycloak keycloakServiceAccount;

    @Named("authz-provider")
    Keycloak keycloakAuthorizationProvider;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("realm")
    public RealmRepresentation getRealm() {
        return keycloakAdmin.realm("quarkus").toRepresentation();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("realm-roles")
    public List<RoleRepresentation> getRealmRoles() {
        return keycloakServiceAccount.realm("quarkus").roles().list();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("realm-names")
    public String[] getRealmNames() {
        return keycloakAuthorizationProvider.realms().findAll().stream().map(RealmRepresentation::getRealm)
                .toArray(String[]::new);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("newrealm")
    public RealmRepresentation createRealm() {
        RealmRepresentation newRealm = createRealm("quarkus2");

        newRealm.getClients().add(createClient("quarkus-app2"));
        newRealm.getUsers().add(createUser("alice", "user"));
        keycloakAdmin.realms().create(newRealm);
        return keycloakAdmin.realm("quarkus2").toRepresentation();
    }

    private static RealmRepresentation createRealm(String name) {
        RealmRepresentation realm = new RealmRepresentation();

        realm.setRealm(name);
        realm.setEnabled(true);
        realm.setUsers(new ArrayList<>());
        realm.setClients(new ArrayList<>());

        RolesRepresentation roles = new RolesRepresentation();
        List<RoleRepresentation> realmRoles = new ArrayList<>();

        roles.setRealm(realmRoles);
        realm.setRoles(roles);

        realm.getRoles().getRealm().add(new RoleRepresentation("user", null, false));

        return realm;
    }

    private static ClientRepresentation createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();

        client.setClientId(clientId);
        client.setRedirectUris(Arrays.asList("*"));
        client.setPublicClient(false);
        client.setSecret("secret");
        client.setDirectAccessGrantsEnabled(true);
        client.setEnabled(true);

        return client;
    }

    private static UserRepresentation createUser(String username, String... realmRoles) {
        UserRepresentation user = new UserRepresentation();

        user.setUsername(username);
        user.setEnabled(true);
        user.setCredentials(new ArrayList<>());
        user.setRealmRoles(Arrays.asList(realmRoles));

        CredentialRepresentation credential = new CredentialRepresentation();

        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(username);
        credential.setTemporary(false);

        user.getCredentials().add(credential);

        return user;
    }
}
