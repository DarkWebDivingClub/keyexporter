package club.dwdc.keyexporter.openpgp;

public record OpenPgpExport(String publicKeyArmor, String secretKeyArmor, String fingerprint) {
}

