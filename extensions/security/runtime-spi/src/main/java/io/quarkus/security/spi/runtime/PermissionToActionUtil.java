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
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("Permission value must not be empty");
        }

        var name = new StringBuilder();
        var action = new StringBuilder();
        boolean buildingAction = false;

        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\') {
                if (i + 1 >= raw.length() || raw.charAt(i + 1) != ':') {
                    throw new IllegalArgumentException(
                            "Invalid escape sequence in permission value '" + raw
                                    + "': backslash is only allowed before a colon (\\:)");
                }
                (buildingAction ? action : name).append(':');
                i++;
            } else if (c == ':' && !buildingAction && !name.isEmpty() && i < raw.length() - 1) {
                buildingAction = true;
            } else if (c == ':' && buildingAction) {
                throw new IllegalArgumentException(
                        "Permission value '" + raw
                                + "' contains more than one unescaped colon separator, use \\: for a literal colon");
            } else {
                (buildingAction ? action : name).append(c);
            }
        }

        if (name.isEmpty()) {
            throw new IllegalArgumentException("Permission value must not be empty");
        }
        return new ParsedPermissionImpl(name.toString(), buildingAction ? action.toString() : null);
    }
}
