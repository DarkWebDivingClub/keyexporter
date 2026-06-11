package club.dwdc.keyexporter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class MetadataJsonTest {
    @TempDir
    Path tempDir;

    @Test
    void roundTripsAuthoritativeMetadata() throws Exception {
        OpenPgpMetadata expected = OpenPgpMetadata.create(
                "Alice", "alice@example.com", "alice@example.com",
                Instant.parse("2026-06-12T00:00:00Z"));
        Path path = tempDir.resolve("alice.json");

        MetadataJson.write(path, expected);

        assertEquals(expected, MetadataJson.read(path));
        String json = MetadataJson.writeString(expected);
        assertFalse(json.contains("mnemonic"));
        assertFalse(json.contains("password"));
    }
}

