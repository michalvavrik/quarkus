package io.quarkus.security.spi;

import java.util.Objects;

import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.security.identity.CurrentIdentityAssociation;

/**
 * Allows Quarkus core extensions to provide their default {@link io.quarkus.security.identity.CurrentIdentityAssociation}.
 * This bean is used to synchronize the association produced by Quarkus core extensions and can change if needed.
 * Other extensions and users can simply define alternative {@link io.quarkus.security.identity.CurrentIdentityAssociation}
 * CDI bean.
 */
public final class DefaultIdentityAssociationClassBuildItem extends SimpleBuildItem {

    private final Class<? extends CurrentIdentityAssociation> currentIdentityAssociationClass;

    public DefaultIdentityAssociationClassBuildItem(
            Class<? extends CurrentIdentityAssociation> currentIdentityAssociationClass) {
        this.currentIdentityAssociationClass = Objects.requireNonNull(currentIdentityAssociationClass);
    }

    public Class<? extends CurrentIdentityAssociation> getIdentityAssociationClass() {
        return currentIdentityAssociationClass;
    }
}
