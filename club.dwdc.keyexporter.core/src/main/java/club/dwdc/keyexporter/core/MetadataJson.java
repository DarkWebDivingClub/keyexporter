package club.dwdc.keyexporter.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MetadataJson {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private MetadataJson() {
    }

    public static OpenPgpMetadata read(Path path) throws IOException {
        return MAPPER.readValue(path.toFile(), OpenPgpMetadata.class);
    }

    public static void write(Path path, OpenPgpMetadata metadata) throws IOException {
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        MAPPER.writeValue(absolute.toFile(), metadata);
    }

    public static String writeString(OpenPgpMetadata metadata) throws IOException {
        return MAPPER.writeValueAsString(metadata);
    }
}

