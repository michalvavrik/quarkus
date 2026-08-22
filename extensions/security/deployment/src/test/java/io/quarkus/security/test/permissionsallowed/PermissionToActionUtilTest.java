package io.quarkus.security.test.permissionsallowed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.quarkus.security.spi.runtime.PermissionToActionUtil;

class PermissionToActionUtilTest {

    private static final String EC = "\\:";
    private static final String EB = "\\\\";

    @Test
    void nameOnly() {
        var result = PermissionToActionUtil.parse("read");
        assertEquals("read", result.name());
        assertNull(result.action());
    }

    @Test
    void nameAndAction() {
        var result = PermissionToActionUtil.parse("read:write");
        assertEquals("read", result.name());
        assertEquals("write", result.action());
    }

    @Test
    void nameWithHyphens() {
        var result = PermissionToActionUtil.parse("my-permission-name");
        assertEquals("my-permission-name", result.name());
        assertNull(result.action());
    }

    @Test
    void actionWithHyphens() {
        var result = PermissionToActionUtil.parse("perm:my-action");
        assertEquals("perm", result.name());
        assertEquals("my-action", result.action());
    }

    @Test
    void singleEscapedColonInName() {
        var result = PermissionToActionUtil.parse("system" + EC + "role");
        assertEquals("system:role", result.name());
        assertNull(result.action());
    }

    @Test
    void multipleEscapedColonsInName() {
        var result = PermissionToActionUtil.parse("a" + EC + "b" + EC + "c");
        assertEquals("a:b:c", result.name());
        assertNull(result.action());
    }

    @Test
    void escapedColonInNameWithSeparatorAndAction() {
        var result = PermissionToActionUtil.parse("system" + EC + "role:query");
        assertEquals("system:role", result.name());
        assertEquals("query", result.action());
    }

    @Test
    void multipleEscapedColonsInNameWithAction() {
        var result = PermissionToActionUtil.parse("a" + EC + "b" + EC + "c:act");
        assertEquals("a:b:c", result.name());
        assertEquals("act", result.action());
    }

    @Test
    void escapedColonInAction() {
        var result = PermissionToActionUtil.parse("name:a" + EC + "b");
        assertEquals("name", result.name());
        assertEquals("a:b", result.action());
    }

    @Test
    void multipleEscapedColonsInAction() {
        var result = PermissionToActionUtil.parse("name:a" + EC + "b" + EC + "c");
        assertEquals("name", result.name());
        assertEquals("a:b:c", result.action());
    }

    @Test
    void escapedColonsInBothNameAndAction() {
        var result = PermissionToActionUtil.parse("n" + EC + "ame:act" + EC + "ion");
        assertEquals("n:ame", result.name());
        assertEquals("act:ion", result.action());
    }

    @Test
    void literalBackslashInName() {
        var result = PermissionToActionUtil.parse("read" + EB + "write");
        assertEquals("read\\write", result.name());
        assertNull(result.action());
    }

    @Test
    void literalBackslashBeforeSeparator() {
        var result = PermissionToActionUtil.parse("read" + EB + ":write");
        assertEquals("read\\", result.name());
        assertEquals("write", result.action());
    }

    @Test
    void literalBackslashFollowedByEscapedColon() {
        var result = PermissionToActionUtil.parse("read" + EB + EC + "write");
        assertEquals("read\\:write", result.name());
        assertNull(result.action());
    }

    @Test
    void twoLiteralBackslashes() {
        var result = PermissionToActionUtil.parse("a" + EB + EB + "b");
        assertEquals("a\\\\b", result.name());
        assertNull(result.action());
    }

    @Test
    void multipleUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b:c"));
    }

    @Test
    void threeUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b:c:d"));
    }

    @Test
    void mixedEscapedAndMultipleUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b" + EC + "c:d"));
    }

    @Test
    void firstEscapedThenMultipleUnescapedFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a" + EC + "b:c:d"));
    }

    @Test
    void emptyStringFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(""));
    }

    @Test
    void onlySeparatorFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(":"));
    }

    @Test
    void leadingColonFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(":action"));
    }

    @Test
    void trailingColon() {
        var result = PermissionToActionUtil.parse("name:");
        assertEquals("name", result.name());
        assertEquals("", result.action());
    }

    @Test
    void escapedColonAsEntireName() {
        var result = PermissionToActionUtil.parse(EC);
        assertEquals(":", result.name());
        assertNull(result.action());
    }

    @Test
    void trailingBackslashFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("read\\"));
    }

    @Test
    void onlyBackslashFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("\\"));
    }

    @Test
    void escapedVsUnescapedColonProduceDifferentResults() {
        var escaped = PermissionToActionUtil.parse("admin" + EC + "read");
        assertEquals("admin:read", escaped.name());
        assertNull(escaped.action());

        var unescaped = PermissionToActionUtil.parse("admin:read");
        assertEquals("admin", unescaped.name());
        assertEquals("read", unescaped.action());

        assertNotEquals(escaped, unescaped);
    }

    @Test
    void escapedColonSeparatorEscapedColon() {
        var result = PermissionToActionUtil.parse(EC + ":" + EC);
        assertEquals(":", result.name());
        assertEquals(":", result.action());
    }

    @Test
    void onlyEscapedBackslashes() {
        var result = PermissionToActionUtil.parse(EB + EB);
        assertEquals("\\\\", result.name());
        assertNull(result.action());
    }

    @Test
    void complexRealWorldPermissionName() {
        var result = PermissionToActionUtil.parse("org" + EC + "acme" + EC + "service:read");
        assertEquals("org:acme:service", result.name());
        assertEquals("read", result.action());
    }

    @Test
    void complexRealWorldPermissionNameNoAction() {
        var result = PermissionToActionUtil.parse("org" + EC + "acme" + EC + "service" + EC + "read");
        assertEquals("org:acme:service:read", result.name());
        assertNull(result.action());
    }

    @Test
    void backslashInActionPart() {
        var result = PermissionToActionUtil.parse("name:path" + EB + "to" + EB + "resource");
        assertEquals("name", result.name());
        assertEquals("path\\to\\resource", result.action());
    }

    @Test
    void originalIssueScenario() {
        var result = PermissionToActionUtil.parse("system" + EC + "role" + EC + "query1");
        assertEquals("system:role:query1", result.name());
        assertNull(result.action());
    }

    @Test
    void originalIssueScenarioWithAction() {
        var result = PermissionToActionUtil.parse("system" + EC + "role:query1");
        assertEquals("system:role", result.name());
        assertEquals("query1", result.action());
    }
}
