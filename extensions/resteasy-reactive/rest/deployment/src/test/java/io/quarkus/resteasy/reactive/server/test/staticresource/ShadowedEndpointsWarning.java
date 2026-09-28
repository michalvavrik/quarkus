package io.quarkus.resteasy.reactive.server.test.staticresource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.logging.LogRecord;
import java.util.stream.Collectors;

import org.jboss.logmanager.Level;

final class ShadowedEndpointsWarning {

    static final String LOGGER = "io.quarkus.resteasy.reactive.server.runtime.StaticResourceShadowingCheck";

    private ShadowedEndpointsWarning() {
    }

    static void assertShadowedEndpoints(List<LogRecord> records, String... expectedEntries) {
        assertEquals(1, records.size(),
                () -> "expected exactly one warning about shadowed endpoints, got: " + messages(records));
        LogRecord record = records.get(0);
        assertEquals(Level.WARN, record.getLevel(),
                () -> "expected a warning, got " + record.getLevel() + ": " + record.getMessage());
        List<String> entries = record.getMessage().lines().map(String::strip).filter(line -> line.contains(" -> "))
                .sorted().toList();
        assertEquals(Arrays.stream(expectedEntries).sorted().toList(), entries,
                () -> "unexpected shadowed endpoints in the warning:\n" + record.getMessage());
    }

    static void assertNoShadowedEndpoints(List<LogRecord> records) {
        assertTrue(records.isEmpty(),
                () -> "expected no warning about shadowed endpoints, got: " + messages(records));
    }

    private static String messages(List<LogRecord> records) {
        return records.stream().map(LogRecord::getMessage).collect(Collectors.joining("\n"));
    }
}
