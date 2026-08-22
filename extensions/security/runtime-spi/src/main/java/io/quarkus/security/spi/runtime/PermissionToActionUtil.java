package io.quarkus.security.spi.runtime;

/**
 * Parses {@code @PermissionsAllowed} value expressions into permission name and optional action.
 * <p>
 * The colon {@code :} is the separator between name and action.
 * A backslash before a colon {@code \:} escapes it as a literal colon character.
 * A double backslash {@code \\} represents a literal backslash.
 */
public final class PermissionToActionUtil {

    public record ParsedPermission(String name, String action) {
        public boolean hasAction() {
            return action != null;
        }
    }

    private PermissionToActionUtil() {
    }

    /**
     * Parse a permission value expression into permission name and optional action.
     *
     * @param raw the raw permission value, e.g. from {@code @PermissionsAllowed} or HTTP security policy config
     * @return parsed permission name and nullable action
     * @throws IllegalArgumentException if the value contains multiple unescaped colons,
     *         has a trailing backslash, or results in an empty permission name
     */
    public static ParsedPermission parse(String raw) {
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
