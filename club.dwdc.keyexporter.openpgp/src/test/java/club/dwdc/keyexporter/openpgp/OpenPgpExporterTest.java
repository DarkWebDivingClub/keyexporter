package club.dwdc.keyexporter.openpgp;

import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenPgpExporterTest {
    private static final OpenPgpKeySeeds SEEDS = new OpenPgpKeySeeds(
            hex("4f2d32ade6250539bb989a7cffd1d5ec882d16864f502632b6d4f087591f0ee1"),
            hex("5f2d32ade6250539bb989a7cffd1d5ec882d16864f502632b6d4f087591f0ee2"),
            hex("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"));
    private static final OpenPgpMetadata METADATA = OpenPgpMetadata.create(
            "Alice", "alice@example.com", "alice@example.com",
            Instant.parse("2025-06-12T00:00:00Z"));

    @Test
    void createsThreeKeyPasswordProtectedRing() throws Exception {
        OpenPgpExport exported = OpenPgpExporter.export(SEEDS, METADATA, "test-password".toCharArray());
        assertTrue(exported.publicKeyArmor().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertTrue(exported.secretKeyArmor().startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        PGPSecretKeyRing ring = new PGPSecretKeyRing(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(
                        exported.secretKeyArmor().getBytes(StandardCharsets.US_ASCII))),
                new BcKeyFingerprintCalculator());
        Iterator<PGPSecretKey> keys = ring.getSecretKeys();

        PGPSecretKey primary = keys.next();
        PGPSecretKey signing = keys.next();
        PGPSecretKey encryption = keys.next();
        assertFalse(keys.hasNext());

        assertTrue(primary.isMasterKey());
        assertEquals(PublicKeyAlgorithmTags.EDDSA, primary.getPublicKey().getAlgorithm());
        assertEquals(PublicKeyAlgorithmTags.EDDSA, signing.getPublicKey().getAlgorithm());
        assertEquals(PublicKeyAlgorithmTags.ECDH, encryption.getPublicKey().getAlgorithm());
        assertTrue(primary.getKeyEncryptionAlgorithm() != 0);
    }

    @Test
    void fingerprintIsDeterministic() throws Exception {
        OpenPgpExport first = OpenPgpExporter.export(SEEDS, METADATA, "first".toCharArray());
        Thread.sleep(1_100);
        OpenPgpExport second = OpenPgpExporter.export(SEEDS, METADATA, "second".toCharArray());
        assertEquals(first.fingerprint(), second.fingerprint());
        assertEquals(first.publicKeyArmor(), second.publicKeyArmor());
    }

    @Test
    void gpgCanImportSignEncryptAndDecrypt(@TempDir Path directory) throws Exception {
        Assumptions.assumeTrue(commandSucceeds("gpg", "--version"), "gpg is not installed");

        OpenPgpExport exported = OpenPgpExporter.export(
                SEEDS, METADATA, "test-password".toCharArray());
        Path home = Files.createDirectory(directory.resolve("gnupg"));
        setOwnerOnly(home);
        Path publicKey = Files.writeString(directory.resolve("public.asc"), exported.publicKeyArmor());
        Path secretKey = Files.writeString(directory.resolve("secret.asc"), exported.secretKeyArmor());
        Path message = Files.writeString(directory.resolve("message.txt"), "OpenPGP interoperability");
        Path signature = directory.resolve("message.sig");
        Path encrypted = directory.resolve("message.gpg");
        Path decrypted = directory.resolve("decrypted.txt");

        run(home, "--import", publicKey.toString());
        run(home, "--import", secretKey.toString());
        String listing = run(home, "--with-colons", "--list-keys", exported.fingerprint());
        assertEquals(1, listing.lines().filter(line -> line.startsWith("pub:")).count());
        assertEquals(2, listing.lines().filter(line -> line.startsWith("sub:")).count());

        run(home, "--pinentry-mode", "loopback", "--passphrase", "test-password",
                "--local-user", exported.fingerprint(), "--output", signature.toString(),
                "--detach-sign", message.toString());
        run(home, "--verify", signature.toString(), message.toString());

        run(home, "--trust-model", "always", "--recipient", exported.fingerprint(),
                "--output", encrypted.toString(), "--encrypt", message.toString());
        run(home, "--pinentry-mode", "loopback", "--passphrase", "test-password",
                "--output", decrypted.toString(), "--decrypt", encrypted.toString());
        assertEquals("OpenPGP interoperability", Files.readString(decrypted));
    }

    private static String run(Path home, String... arguments) throws Exception {
        String[] command = new String[arguments.length + 5];
        command[0] = "gpg";
        command[1] = "--batch";
        command[2] = "--yes";
        command[3] = "--homedir";
        command[4] = home.toString();
        System.arraycopy(arguments, 0, command, 5, arguments.length);

        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int status = process.waitFor();
        assertEquals(0, status, () -> String.join(" ", command) + System.lineSeparator() + output);
        return output;
    }

    private static boolean commandSucceeds(String... command) {
        try {
            return new ProcessBuilder(command).start().waitFor() == 0;
        } catch (IOException exception) {
            return false;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void setOwnerOnly(Path directory) throws IOException {
        try {
            Files.setPosixFilePermissions(directory, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException ignored) {
            // GnuPG accepts the platform's native directory permissions.
        }
    }

    private static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }
}
