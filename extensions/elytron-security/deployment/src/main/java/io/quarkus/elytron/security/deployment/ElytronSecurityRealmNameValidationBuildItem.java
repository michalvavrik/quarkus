package io.quarkus.elytron.security.deployment;

import java.util.Objects;

import org.wildfly.security.auth.server.SecurityRealm;

import io.quarkus.builder.item.MultiBuildItem;

/**
 * This build item should be registered for each {@link SecurityRealm} service the produce in order to prevent
 * conflicts between realms as Elytron only support one realm with the same name.
 */
public final class ElytronSecurityRealmNameValidationBuildItem extends MultiBuildItem {

    final String realmName;
    final String realmNameConfigProperty;
    final String extensionName;

    public ElytronSecurityRealmNameValidationBuildItem(String realmName, String realmNameConfigProperty, String extensionName) {
        this.realmName = Objects.requireNonNull(realmName);
        this.realmNameConfigProperty = Objects.requireNonNull(realmNameConfigProperty);
        this.extensionName = Objects.requireNonNull(extensionName);
    }
}
