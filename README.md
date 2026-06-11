# club.dwdc.keyexporter

Java 21 command-line exporters for deterministic keys derived by DWDC KeyVault.

The initial OpenPGP profile creates:

- Ed25519 primary key for certification
- Ed25519 signing subkey
- X25519 encryption subkey
- OpenPGP v4 public and password-protected secret key rings

## Build

Install `club.dwdc.keyvault` first:

```sh
cd ~/git/club.dwdc.keyvault
mvn install
```

Then build KeyExporter:

```sh
cd ~/git/club.dwdc.keyexporter
mvn verify
```

The executable JAR is:

```text
club.dwdc.keyexporter.cli/target/club.dwdc.keyexporter.cli-0.1.0-SNAPSHOT.jar
```

## Usage

Create authoritative OpenPGP metadata:

```sh
java -jar club.dwdc.keyexporter.cli/target/club.dwdc.keyexporter.cli-0.1.0-SNAPSHOT.jar \
  openpgp init \
  --name "Alice" \
  --email "alice@example.com" \
  --output alice-openpgp.json
```

Export a public key:

```sh
java -jar club.dwdc.keyexporter.cli/target/club.dwdc.keyexporter.cli-0.1.0-SNAPSHOT.jar \
  openpgp export \
  --metadata alice-openpgp.json \
  --mnemonic-file /secure/path/seed.txt \
  --public alice-public.asc
```

Add `--secret alice-secret.asc` to export a password-protected secret key. The
CLI prompts for the password. For non-interactive execution, name an environment
variable with `--password-env`.

The metadata contains no mnemonic, derived private seed, BIP-39 passphrase, or
secret-key password.

