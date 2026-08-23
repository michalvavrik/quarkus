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
        int separatorIdx = findSeparator(raw);
        if (separatorIdx < 0) {
            return new ParsedPermissionImpl(unescape(raw), null);
        }
        return new ParsedPermissionImpl(
                unescape(raw.substring(0, separatorIdx)),
                unescape(raw.substring(separatorIdx + 1)));
    }

    private static int findSeparator(String raw) {
        int separatorIdx = -1;
        for (int i = 0; i < raw.length(); i++) {
            if (raw.charAt(i) == '\\') {
                i++;
            } else if (raw.charAt(i) == ':' && i > 0 && i < raw.length() - 1) {
                if (separatorIdx >= 0) {
                    throw new IllegalArgumentException(
                            "Permission value '" + raw
                                    + "' contains more than one unescaped colon separator, use \\: for a literal colon");
                }
                separatorIdx = i;
            }
        }
        return separatorIdx;
    }

    private static String unescape(String part) {
        if (part.indexOf('\\') < 0) {
            return part;
        }
        var sb = new StringBuilder(part.length());
        for (int i = 0; i < part.length(); i++) {
            if (part.charAt(i) == '\\') {
                if (i + 1 >= part.length() || part.charAt(i + 1) != ':') {
                    throw new IllegalArgumentException(
                            "Invalid escape sequence in permission value: backslash is only allowed before a colon (\\:)");
                }
                sb.append(':');
                i++;
            } else {
                sb.append(part.charAt(i));
            }
        }
        return sb.toString();
    }
}
