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
            } else if (c == ':') {
                if (buildingAction) {
                    throw new IllegalArgumentException(
                            "Permission value '" + raw
                                    + "' contains more than one unescaped colon separator, use \\: for a literal colon");
                }
                if (name.isEmpty() || (name.length() == 1 && name.charAt(0) == ':')) {
                    throw new IllegalArgumentException(
                            "Invalid permission name in value '" + raw + "'");
                }
                buildingAction = true;
            } else {
                (buildingAction ? action : name).append(c);
            }
        }

        if (!buildingAction) {
            if (name.isEmpty() || (name.length() == 1 && name.charAt(0) == ':')) {
                throw new IllegalArgumentException(
                        "Invalid permission name in value '" + raw + "'");
            }
            return new ParsedPermissionImpl(name.toString(), null);
        }
        return new ParsedPermissionImpl(name.toString(), action.toString());
    }
}
