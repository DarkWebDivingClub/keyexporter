package club.dwdc.keyexporter.cli;

import club.dwdc.keyexporter.core.MetadataJson;
import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import club.dwdc.keyexporter.core.OpenPgpSeedDeriver;
import club.dwdc.keyexporter.openpgp.OpenPgpExport;
import club.dwdc.keyexporter.openpgp.OpenPgpExporter;
import club.dwdc.keyvault.core.Bip32KeyVault;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(
        name = "keyexport",
        mixinStandardHelpOptions = true,
        version = "0.1.0-SNAPSHOT",
        description = "Export deterministic keys from DWDC KeyVault.",
        subcommands = {KeyExporterCli.OpenPgpCommand.class})
public final class KeyExporterCli implements Callable<Integer> {
    public static void main(String[] args) {
        System.exit(new CommandLine(new KeyExporterCli()).execute(args));
    }

    @Override
    public Integer call() {
        new CommandLine(this).usage(System.out);
        return 0;
    }

    @Command(
            name = "openpgp",
            description = "OpenPGP metadata and export operations.",
            subcommands = {InitCommand.class, ExportCommand.class})
    static final class OpenPgpCommand implements Callable<Integer> {
        @Override
        public Integer call() {
            return 0;
        }
    }

    @Command(name = "init", mixinStandardHelpOptions = true,
            description = "Create authoritative OpenPGP export metadata.")
    static final class InitCommand implements Callable<Integer> {
        @Option(names = "--name", required = true, description = "OpenPGP user name.")
        String name;

        @Option(names = "--email", required = true, description = "OpenPGP user email.")
        String email;

        @Option(names = "--identity",
                description = "KeyVault identity. Defaults to the email address.")
        String identity;

        @Option(names = "--creation-time",
                description = "UTC key creation instant. Defaults to the current time.")
        Instant creationTime;

        @Option(names = "--output", required = true, description = "Metadata JSON output path.")
        Path output;

        @Option(names = "--force", description = "Overwrite an existing metadata file.")
        boolean force;

        @Override
        public Integer call() throws Exception {
            if (Files.exists(output) && !force) {
                throw new IllegalArgumentException("File exists: " + output + " (use --force)");
            }
            String effectiveIdentity = identity == null ? email : identity;
            Instant effectiveCreationTime = creationTime == null
                    ? Instant.now().truncatedTo(ChronoUnit.SECONDS)
                    : creationTime.truncatedTo(ChronoUnit.SECONDS);
            OpenPgpMetadata metadata =
                    OpenPgpMetadata.create(name, email, effectiveIdentity, effectiveCreationTime);
            MetadataJson.write(output, metadata);
            System.out.println("Metadata: " + output.toAbsolutePath());
            return 0;
        }
    }

    @Command(name = "export", mixinStandardHelpOptions = true,
            description = "Export deterministic OpenPGP public and secret key rings.")
    static final class ExportCommand implements Callable<Integer> {
        @Option(names = "--metadata", required = true, description = "Authoritative metadata JSON.")
        Path metadataPath;

        @Option(names = "--mnemonic-file", required = true,
                description = "File containing the BIP-39 mnemonic.")
        Path mnemonicFile;

        @Option(names = "--passphrase-env",
                description = "Environment variable containing the optional BIP-39 passphrase.")
        String passphraseEnvironment;

        @Option(names = "--password-env",
                description = "Environment variable containing the secret-key export password.")
        String passwordEnvironment;

        @Option(names = "--public", required = true, description = "ASCII-armored public-key path.")
        Path publicPath;

        @Option(names = "--secret", description = "ASCII-armored secret-key path.")
        Path secretPath;

        @Option(names = "--force", description = "Overwrite existing output files.")
        boolean force;

        @Override
        public Integer call() throws Exception {
            checkOutput(publicPath);
            if (secretPath != null) {
                checkOutput(secretPath);
            }

            OpenPgpMetadata metadata = MetadataJson.read(metadataPath);
            String mnemonic = Files.readString(mnemonicFile).strip();
            if (mnemonic.isEmpty()) {
                throw new IllegalArgumentException("Mnemonic file is empty: " + mnemonicFile);
            }
            String passphrase = readEnvironment(passphraseEnvironment, "");
            char[] password = secretPath == null
                    ? temporaryPassword()
                    : readSecretPassword();

            try {
                Bip32KeyVault vault = new Bip32KeyVault(mnemonic, passphrase);
                OpenPgpKeySeeds seeds = OpenPgpSeedDeriver.derive(vault, metadata.identity());
                OpenPgpExport exported = OpenPgpExporter.export(seeds, metadata, password);

                write(publicPath, exported.publicKeyArmor(), false);
                if (secretPath != null) {
                    write(secretPath, exported.secretKeyArmor(), true);
                }
                System.out.println("Fingerprint: " + exported.fingerprint());
                System.out.println("Public key: " + publicPath.toAbsolutePath());
                if (secretPath != null) {
                    System.out.println("Secret key: " + secretPath.toAbsolutePath());
                }
                return 0;
            } finally {
                Arrays.fill(password, '\0');
            }
        }

        private void checkOutput(Path path) {
            if (Files.exists(path) && !force) {
                throw new IllegalArgumentException("File exists: " + path + " (use --force)");
            }
        }

        private char[] readSecretPassword() {
            if (passwordEnvironment != null) {
                String value = System.getenv(passwordEnvironment);
                if (value == null || value.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Environment variable is unset or empty: " + passwordEnvironment);
                }
                return value.toCharArray();
            }
            Console console = System.console();
            if (console == null) {
                throw new IllegalArgumentException(
                        "No interactive console; use --password-env for secret-key export");
            }
            char[] first = console.readPassword("Secret-key password: ");
            char[] second = console.readPassword("Confirm password: ");
            if (first == null || first.length == 0 || !Arrays.equals(first, second)) {
                if (first != null) {
                    Arrays.fill(first, '\0');
                }
                if (second != null) {
                    Arrays.fill(second, '\0');
                }
                throw new IllegalArgumentException("Passwords are empty or do not match");
            }
            Arrays.fill(second, '\0');
            return first;
        }

        private static char[] temporaryPassword() {
            return "public-export-only".toCharArray();
        }

        private static String readEnvironment(String name, String defaultValue) {
            if (name == null) {
                return defaultValue;
            }
            String value = System.getenv(name);
            if (value == null) {
                throw new IllegalArgumentException("Environment variable is unset: " + name);
            }
            return value;
        }

        private static void write(Path path, String value, boolean privateFile) throws Exception {
            Path absolute = path.toAbsolutePath();
            Path parent = absolute.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(absolute, value);
            if (privateFile) {
                try {
                    Files.setPosixFilePermissions(absolute, Set.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE));
                } catch (UnsupportedOperationException ignored) {
                    // Non-POSIX filesystems do not expose Unix file modes.
                }
            }
        }
    }
}

