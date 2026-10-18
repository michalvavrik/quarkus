package io.quarkus.elytron.security.deployment;

import java.util.Objects;

import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;

import io.quarkus.builder.item.MultiBuildItem;

/**
 * Declares a {@link SecurityRealm} that a realm extension (properties file, JDBC, LDAP or OAuth2) registers as a
 * runtime service under {@link #getServiceName()}. The Elytron security extension combines the declared realms into a
 * single {@linkplain SecurityDomain}.
 * <p>
 * The realms are added to the security domain in the order of this build item list and the first realm becomes the
 * default realm of the domain, that is the realm which authenticates a user name and password unless a
 * {@linkplain RealmMapper} bean maps the request to another realm. This is the order in which the bytecode recorder
 * based implementation collected its realm build items, so a realm extension must produce this build item from the
 * build step that used to produce the realm build item. Realms that {@linkplain #requiresBeanContainer require the
 * bean container} are added after all other realms, because the build steps creating them consumed the bean container
 * build item and therefore ran after the other realm build steps.
 * <p>
 * When several realms declare the same realm name, the realm added last replaces the realms added before it.
 */
public final class ElytronSecurityRealmBuildItem extends MultiBuildItem {

    private static final String SERVICE_NAME_PREFIX = "io.quarkus.elytron-security.realm.";

    /**
     * Identifies the realm source within the extension, for example {@code jdbc} or {@code properties-embedded}.
     */
    final String source;
    final String realmName;
    /**
     * The configuration property that defines the realm name, or {@code null} when the realm name is fixed.
     */
    final String realmNameConfigProperty;
    final String extensionName;
    /**
     * Whether the realm can only be created once the bean container is available, see the class documentation for
     * the effect on the order of the realms in the security domain.
     */
    final boolean requiresBeanContainer;

    /**
     * Declares a realm whose name is defined by a configuration property.
     *
     * @param source a short identifier of the realm source, unique within the extension
     * @param realmName the realm name
     * @param realmNameConfigProperty the configuration property that defines the realm name
     * @param extensionName the name of the extension that registers the realm
     * @param requiresBeanContainer whether the realm can only be created once the bean container is available
     */
    public ElytronSecurityRealmBuildItem(String source, String realmName, String realmNameConfigProperty,
            String extensionName, boolean requiresBeanContainer) {
        this.source = Objects.requireNonNull(source);
        this.realmName = Objects.requireNonNull(realmName);
        this.realmNameConfigProperty = Objects.requireNonNull(realmNameConfigProperty);
        this.extensionName = Objects.requireNonNull(extensionName);
        this.requiresBeanContainer = requiresBeanContainer;
    }

    /**
     * Declares a realm whose name is fixed, that is, not configurable.
     *
     * @param source a short identifier of the realm source, unique within the extension
     * @param realmName the realm name
     * @param extensionName the name of the extension that registers the realm
     * @param requiresBeanContainer whether the realm can only be created once the bean container is available
     */
    public ElytronSecurityRealmBuildItem(String source, String realmName, String extensionName,
            boolean requiresBeanContainer) {
        this.source = Objects.requireNonNull(source);
        this.realmName = Objects.requireNonNull(realmName);
        this.realmNameConfigProperty = null;
        this.extensionName = Objects.requireNonNull(extensionName);
        this.requiresBeanContainer = requiresBeanContainer;
    }

    /**
     * The name under which the realm extension must register the {@link SecurityRealm} service. The name includes the
     * realm source, so realms sharing a realm name can still be registered as distinct services.
     *
     * @return the service name
     */
    public String getServiceName() {
        return SERVICE_NAME_PREFIX + source + "." + realmName;
    }

    public String getRealmName() {
        return realmName;
    }

    String describe() {
        if (realmNameConfigProperty == null) {
            return extensionName + " (the realm name is fixed)";
        }
        return extensionName + " ('" + realmNameConfigProperty + "')";
    }
}
