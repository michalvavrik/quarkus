package io.quarkus.security.test.permissionsallowed;

import static io.quarkus.security.spi.runtime.PermissionToActionUtil.parse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PermissionToActionUtilTest {

    private static final String ESCAPED_COLON = "\\:";
    private static final String ESCAPED_BACKSLASH = "\\\\";

    @Test
    void nameOnly() {
        var result = parse("read");
        assertEquals("read", result.name());
        assertNull(result.action());
    }

    @Test
    void nameAndAction() {
        var result = parse("read:write");
        assertEquals("read", result.name());
        assertEquals("write", result.action());
    }

    @Test
    void nameWithHyphens() {
        var result = parse("my-permission-name");
        assertEquals("my-permission-name", result.name());
        assertNull(result.action());
    }

    @Test
    void actionWithHyphens() {
        var result = parse("perm:my-action");
        assertEquals("perm", result.name());
        assertEquals("my-action", result.action());
    }

    @Test
    void singleEscapedColonInName() {
        var result = parse("system" + ESCAPED_COLON + "role");
        assertEquals("system:role", result.name());
        assertNull(result.action());
    }

    @Test
    void multipleEscapedColonsInName() {
        var result = parse("a" + ESCAPED_COLON + "b" + ESCAPED_COLON + "c");
        assertEquals("a:b:c", result.name());
        assertNull(result.action());
    }

    @Test
    void escapedColonInNameWithSeparatorAndAction() {
        var result = parse("system" + ESCAPED_COLON + "role:query");
        assertEquals("system:role", result.name());
        assertEquals("query", result.action());
    }

    @Test
    void multipleEscapedColonsInNameWithAction() {
        var result = parse("a" + ESCAPED_COLON + "b" + ESCAPED_COLON + "c:act");
        assertEquals("a:b:c", result.name());
        assertEquals("act", result.action());
    }

    @Test
    void escapedColonInAction() {
        var result = parse("name:a" + ESCAPED_COLON + "b");
        assertEquals("name", result.name());
        assertEquals("a:b", result.action());
    }

    @Test
    void multipleEscapedColonsInAction() {
        var result = parse("name:a" + ESCAPED_COLON + "b" + ESCAPED_COLON + "c");
        assertEquals("name", result.name());
        assertEquals("a:b:c", result.action());
    }

    @Test
    void escapedColonsInBothNameAndAction() {
        var result = parse("n" + ESCAPED_COLON + "ame:act" + ESCAPED_COLON + "ion");
        assertEquals("n:ame", result.name());
        assertEquals("act:ion", result.action());
    }

    @Test
    void literalBackslashInName() {
        var result = parse("read" + ESCAPED_BACKSLASH + "write");
        assertEquals("read\\write", result.name());
        assertNull(result.action());
    }

    @Test
    void literalBackslashBeforeSeparator() {
        var result = parse("read" + ESCAPED_BACKSLASH + ":write");
        assertEquals("read\\", result.name());
        assertEquals("write", result.action());
    }

    @Test
    void literalBackslashFollowedByEscapedColon() {
        var result = parse("read" + ESCAPED_BACKSLASH + ESCAPED_COLON + "write");
        assertEquals("read\\:write", result.name());
        assertNull(result.action());
    }

    @Test
    void twoLiteralBackslashes() {
        var result = parse("a" + ESCAPED_BACKSLASH + ESCAPED_BACKSLASH + "b");
        assertEquals("a\\\\b", result.name());
        assertNull(result.action());
    }

    @Test
    void multipleUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("a:b:c"));
    }

    @Test
    void threeUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("a:b:c:d"));
    }

    @Test
    void mixedEscapedAndMultipleUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("a:b" + ESCAPED_COLON + "c:d"));
    }

    @Test
    void firstEscapedThenMultipleUnescapedFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("a" + ESCAPED_COLON + "b:c:d"));
    }

    @Test
    void emptyStringFails() {
        assertThrows(IllegalArgumentException.class, () -> parse(""));
    }

    @Test
    void onlySeparatorFails() {
        assertThrows(IllegalArgumentException.class, () -> parse(":"));
    }

    @Test
    void leadingColonFails() {
        assertThrows(IllegalArgumentException.class, () -> parse(":action"));
    }

    @Test
    void trailingColon() {
        var result = parse("name:");
        assertEquals("name", result.name());
        assertEquals("", result.action());
    }

    @Test
    void standaloneEscapedColonFails() {
        assertThrows(IllegalArgumentException.class, () -> parse(ESCAPED_COLON));
    }

    @Test
    void trailingBackslashFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("read\\"));
    }

    @Test
    void standaloneBackslashFails() {
        assertThrows(IllegalArgumentException.class, () -> parse("\\"));
    }

    @Test
    void escapedVsUnescapedColonProduceDifferentResults() {
        var escaped = parse("admin" + ESCAPED_COLON + "read");
        assertEquals("admin:read", escaped.name());
        assertNull(escaped.action());

        var unescaped = parse("admin:read");
        assertEquals("admin", unescaped.name());
        assertEquals("read", unescaped.action());

        assertNotEquals(escaped, unescaped);
    }

    @Test
    void separatorOnlyNameAndActionFails() {
        assertThrows(IllegalArgumentException.class, () -> parse(ESCAPED_COLON + ":" + ESCAPED_COLON));
    }

    @Test
    void onlyEscapedBackslashes() {
        var result = parse(ESCAPED_BACKSLASH + ESCAPED_BACKSLASH);
        assertEquals("\\\\", result.name());
        assertNull(result.action());
    }

    @Test
    void namespacedPermissionWithAction() {
        var result = parse("org" + ESCAPED_COLON + "acme" + ESCAPED_COLON + "service:read");
        assertEquals("org:acme:service", result.name());
        assertEquals("read", result.action());
    }

    @Test
    void namespacedPermissionAllEscaped() {
        var result = parse("org" + ESCAPED_COLON + "acme" + ESCAPED_COLON + "service" + ESCAPED_COLON + "read");
        assertEquals("org:acme:service:read", result.name());
        assertNull(result.action());
    }

    @Test
    void backslashInActionPart() {
        var result = parse("name:path" + ESCAPED_BACKSLASH + "to" + ESCAPED_BACKSLASH + "resource");
        assertEquals("name", result.name());
        assertEquals("path\\to\\resource", result.action());
    }
}
