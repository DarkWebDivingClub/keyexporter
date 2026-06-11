package club.dwdc.keyexporter.core;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.time.Instant;
import java.util.Objects;

@JsonPropertyOrder({
        "profileVersion", "identity", "userId", "creationTime", "format", "keyProfile"
})
public record OpenPgpMetadata(
        int profileVersion,
        String identity,
        UserId userId,
        Instant creationTime,
        String format,
        String keyProfile
) {
    public static final int CURRENT_PROFILE_VERSION = 1;
    public static final String FORMAT = "OPENPGP_V4";
    public static final String KEY_PROFILE = "ED25519_CERTIFY_ED25519_SIGN_X25519_ENCRYPT_V1";

    public OpenPgpMetadata {
        if (profileVersion != CURRENT_PROFILE_VERSION) {
            throw new IllegalArgumentException("Unsupported profileVersion: " + profileVersion);
        }
        identity = requireText(identity, "identity");
        userId = Objects.requireNonNull(userId, "userId");
        creationTime = Objects.requireNonNull(creationTime, "creationTime");
        if (!FORMAT.equals(format)) {
            throw new IllegalArgumentException("Unsupported format: " + format);
        }
        if (!KEY_PROFILE.equals(keyProfile)) {
            throw new IllegalArgumentException("Unsupported keyProfile: " + keyProfile);
        }
    }

    public static OpenPgpMetadata create(String name, String email, String identity, Instant creationTime) {
        return new OpenPgpMetadata(
                CURRENT_PROFILE_VERSION,
                identity,
                new UserId(name, email),
                creationTime,
                FORMAT,
                KEY_PROFILE);
    }

    public String formattedUserId() {
        return userId.name() + " <" + userId.email() + ">";
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.strip();
    }

    public record UserId(String name, String email) {
        public UserId {
            name = requireText(name, "userId.name");
            email = requireText(email, "userId.email");
            if (!email.contains("@")) {
                throw new IllegalArgumentException("userId.email must contain '@'");
            }
        }
    }
}

