package club.dwdc.keyexporter.cli;

import club.dwdc.keyexporter.core.MetadataJson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyExporterCliTest {
    @TempDir
    Path tempDir;

    @Test
    void initWritesVersionedMetadata() throws Exception {
        Path output = tempDir.resolve("alice.json");
        int exitCode = new CommandLine(new KeyExporterCli()).execute(
                "openpgp", "init",
                "--name", "Alice",
                "--email", "alice@example.com",
                "--creation-time", "2026-06-12T00:00:00Z",
                "--output", output.toString());

        assertEquals(0, exitCode);
        assertEquals("alice@example.com", MetadataJson.read(output).identity());
    }
}

