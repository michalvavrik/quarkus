package io.quarkus.security.test.permissionsallowed;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.quarkus.security.spi.runtime.PermissionToActionUtil;

/**
 * Unit tests for {@link PermissionToActionUtil#parse(String)}.
 * <p>
 * In all test comments, "input string" refers to the actual character sequence
 * our parser receives at runtime (after Java string literal escaping).
 * In Java source: {@code "\\"} produces a single {@code \} character.
 */
public class PermissionToActionUtilTest {

    // === Basic parsing (no escape characters) ===

    @Test
    public void nameOnly() {
        var result = PermissionToActionUtil.parse("read");
        assertEquals("read", result.name());
        assertNull(result.action());
    }

    @Test
    public void nameAndAction() {
        var result = PermissionToActionUtil.parse("read:write");
        assertEquals("read", result.name());
        assertEquals("write", result.action());
    }

    @Test
    public void nameWithHyphens() {
        var result = PermissionToActionUtil.parse("my-permission-name");
        assertEquals("my-permission-name", result.name());
        assertNull(result.action());
    }

    @Test
    public void actionWithHyphens() {
        var result = PermissionToActionUtil.parse("perm:my-action");
        assertEquals("perm", result.name());
        assertEquals("my-action", result.action());
    }

    // === Escaped colons in the permission NAME ===

    @Test
    public void singleEscapedColonInName() {
        // input: system\:role  ->  name="system:role", no action
        var result = PermissionToActionUtil.parse("system\\:role");
        assertEquals("system:role", result.name());
        assertNull(result.action());
    }

    @Test
    public void multipleEscapedColonsInName() {
        // input: a\:b\:c  ->  name="a:b:c", no action
        var result = PermissionToActionUtil.parse("a\\:b\\:c");
        assertEquals("a:b:c", result.name());
        assertNull(result.action());
    }

    @Test
    public void escapedColonInNameWithSeparatorAndAction() {
        // input: system\:role:query  ->  name="system:role", action="query"
        var result = PermissionToActionUtil.parse("system\\:role:query");
        assertEquals("system:role", result.name());
        assertEquals("query", result.action());
    }

    @Test
    public void multipleEscapedColonsInNameWithAction() {
        // input: a\:b\:c:act  ->  name="a:b:c", action="act"
        var result = PermissionToActionUtil.parse("a\\:b\\:c:act");
        assertEquals("a:b:c", result.name());
        assertEquals("act", result.action());
    }

    // === Escaped colons in the ACTION ===

    @Test
    public void escapedColonInAction() {
        // input: name:a\:b  ->  name="name", action="a:b"
        var result = PermissionToActionUtil.parse("name:a\\:b");
        assertEquals("name", result.name());
        assertEquals("a:b", result.action());
    }

    @Test
    public void multipleEscapedColonsInAction() {
        // input: name:a\:b\:c  ->  name="name", action="a:b:c"
        var result = PermissionToActionUtil.parse("name:a\\:b\\:c");
        assertEquals("name", result.name());
        assertEquals("a:b:c", result.action());
    }

    // === Escaped colons in BOTH name and action ===

    @Test
    public void escapedColonsInBothNameAndAction() {
        // input: n\:ame:act\:ion  ->  name="n:ame", action="act:ion"
        var result = PermissionToActionUtil.parse("n\\:ame:act\\:ion");
        assertEquals("n:ame", result.name());
        assertEquals("act:ion", result.action());
    }

    // === Escaped backslashes ===

    @Test
    public void literalBackslashInName() {
        // input: read\\write (chars: r,e,a,d,\,\,w,r,i,t,e) -> name="read\write", no action
        var result = PermissionToActionUtil.parse("read\\\\write");
        assertEquals("read\\write", result.name());
        assertNull(result.action());
    }

    @Test
    public void literalBackslashBeforeSeparator() {
        // input: read\\:write (chars: r,e,a,d,\,\,:,w,...) -> name="read\", action="write"
        // The \\ is an escaped backslash (literal \), the : is the separator
        var result = PermissionToActionUtil.parse("read\\\\:write");
        assertEquals("read\\", result.name());
        assertEquals("write", result.action());
    }

    @Test
    public void literalBackslashFollowedByEscapedColon() {
        // input: read\\\:write (chars: r,e,a,d,\,\,\,:,w,...) -> name="read\:write", no action
        // \\ = literal backslash, \: = literal colon -> "read\:write"
        var result = PermissionToActionUtil.parse("read\\\\\\:write");
        assertEquals("read\\:write", result.name());
        assertNull(result.action());
    }

    @Test
    public void twoLiteralBackslashes() {
        // input: a\\\\b (chars: a,\,\,\,\,b) -> name="a\\b", no action
        var result = PermissionToActionUtil.parse("a\\\\\\\\b");
        assertEquals("a\\\\b", result.name());
        assertNull(result.action());
    }

    // === Multiple unescaped colons — must fail ===

    @Test
    public void multipleUnescapedColonsFails() {
        // input: a:b:c -> two unescaped colons -> error
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b:c"));
    }

    @Test
    public void threeUnescapedColonsFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b:c:d"));
    }

    @Test
    public void mixedEscapedAndMultipleUnescapedColonsFails() {
        // input: a:b\:c:d -> unescaped colons at positions 1 and 6
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a:b\\:c:d"));
    }

    @Test
    public void firstEscapedThenMultipleUnescapedFails() {
        // input: a\:b:c:d -> unescaped colons at positions 4 and 6
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("a\\:b:c:d"));
    }

    // === Edge cases ===

    @Test
    public void emptyStringFails() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(""));
    }

    @Test
    public void onlySeparatorFails() {
        // input: :  ->  empty permission name
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(":"));
    }

    @Test
    public void leadingColonFails() {
        // input: :action  ->  empty permission name
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse(":action"));
    }

    @Test
    public void trailingColon() {
        // input: name:  ->  name="name", action="" (empty action is allowed)
        var result = PermissionToActionUtil.parse("name:");
        assertEquals("name", result.name());
        assertEquals("", result.action());
    }

    @Test
    public void escapedColonAsEntireName() {
        // input: \:  ->  name=":", no action
        var result = PermissionToActionUtil.parse("\\:");
        assertEquals(":", result.name());
        assertNull(result.action());
    }

    @Test
    public void trailingBackslashFails() {
        // input: read\  ->  dangling escape
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("read\\"));
    }

    @Test
    public void onlyBackslashFails() {
        // input: \  ->  dangling escape
        assertThrows(IllegalArgumentException.class,
                () -> PermissionToActionUtil.parse("\\"));
    }

    // === Attacker/confusion scenarios ===

    @Test
    public void escapedVsUnescapedColonProduceDifferentResults() {
        // "admin\:read" -> ("admin:read", null) — escaped, entire string is the name
        var escaped = PermissionToActionUtil.parse("admin\\:read");
        assertEquals("admin:read", escaped.name());
        assertNull(escaped.action());

        // "admin:read" -> ("admin", "read") — unescaped, colon is separator
        var unescaped = PermissionToActionUtil.parse("admin:read");
        assertEquals("admin", unescaped.name());
        assertEquals("read", unescaped.action());

        // These MUST produce different parsed results — an attacker cannot
        // bypass the separator by escaping
        assertNotEquals(escaped, unescaped);
    }

    @Test
    public void escapedColonSeparatorEscapedColon() {
        // input: \::\:  ->  name=":", action=":"
        var result = PermissionToActionUtil.parse("\\::\\:");
        assertEquals(":", result.name());
        assertEquals(":", result.action());
    }

    @Test
    public void onlyEscapedBackslashes() {
        // input: \\\\ (chars: \,\,\,\) -> name="\\" (two backslashes unescaped to one... wait)
        // Actually: four chars \,\,\,\ -> \\=literal-backslash, \\=literal-backslash -> name="\\"
        // In Java source: parse("\\\\\\\\") which is the string \\\\
        var result = PermissionToActionUtil.parse("\\\\\\\\");
        assertEquals("\\\\", result.name());
        assertNull(result.action());
    }

    @Test
    public void complexRealWorldPermissionName() {
        // Simulates a namespace-style permission: "org\:acme\:service:read"
        // -> name="org:acme:service", action="read"
        var result = PermissionToActionUtil.parse("org\\:acme\\:service:read");
        assertEquals("org:acme:service", result.name());
        assertEquals("read", result.action());
    }

    @Test
    public void complexRealWorldPermissionNameNoAction() {
        // "org\:acme\:service\:read" (all colons escaped) -> name="org:acme:service:read", no action
        var result = PermissionToActionUtil.parse("org\\:acme\\:service\\:read");
        assertEquals("org:acme:service:read", result.name());
        assertNull(result.action());
    }

    @Test
    public void backslashInActionPart() {
        // input: name:path\\to\\resource -> name="name", action="path\to\resource"
        var result = PermissionToActionUtil.parse("name:path\\\\to\\\\resource");
        assertEquals("name", result.name());
        assertEquals("path\\to\\resource", result.action());
    }

    @Test
    public void originalIssueScenario() {
        // The original issue: @PermissionsAllowed("system:role:query1") fails.
        // With escaping: "system\:role\:query1" -> name="system:role:query1", no action
        var result = PermissionToActionUtil.parse("system\\:role\\:query1");
        assertEquals("system:role:query1", result.name());
        assertNull(result.action());
    }

    @Test
    public void originalIssueScenarioWithAction() {
        // Variant: "system\:role:query1" -> name="system:role", action="query1"
        var result = PermissionToActionUtil.parse("system\\:role:query1");
        assertEquals("system:role", result.name());
        assertEquals("query1", result.action());
    }
}
