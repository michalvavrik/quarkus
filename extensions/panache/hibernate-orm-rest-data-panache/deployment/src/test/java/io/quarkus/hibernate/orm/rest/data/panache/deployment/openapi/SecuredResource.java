package io.quarkus.hibernate.orm.rest.data.panache.deployment.openapi;

import jakarta.annotation.security.RolesAllowed;

import io.quarkus.hibernate.orm.rest.data.panache.PanacheRepositoryResource;
import io.quarkus.rest.data.panache.ResourceProperties;
import io.quarkus.security.PermissionsAllowed;

@ResourceProperties(path = "secured")
public interface SecuredResource extends PanacheRepositoryResource<ItemsRepository, Item, Long> {

    @RolesAllowed("admin")
    long count();

    @PermissionsAllowed("get")
    Item get(Long id);
}
