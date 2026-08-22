package io.quarkus.security.spi.runtime;

public final class PermissionToActionUtil {

    public sealed interface ParsedPermission {
        String name();

        String action();

        default boolean hasAction() {
            return action() != null;
        }
    }

    record ParsedPermissionImpl(String name, String action) implements ParsedPermission {
    }

    private PermissionToActionUtil() {
    }

    public static ParsedPermission parse(String raw) {
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
