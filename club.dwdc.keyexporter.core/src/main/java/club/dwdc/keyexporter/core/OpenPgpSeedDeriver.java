package club.dwdc.keyexporter.core;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;

public final class OpenPgpSeedDeriver {
    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int OPENPGP = Protocol.OPENPGP.coinType() | H;
    private static final int CONFIG = new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    public static final int CERTIFICATION_ROLE = 0;
    public static final int SIGNING_ROLE = 1;
    public static final int ENCRYPTION_ROLE = 2;

    private OpenPgpSeedDeriver() {
    }

    public static OpenPgpKeySeeds derive(KeyVault vault, String identity) {
        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        return new OpenPgpKeySeeds(
                derive(vault, identityIndex, CERTIFICATION_ROLE),
                derive(vault, identityIndex, SIGNING_ROLE),
                derive(vault, identityIndex, ENCRYPTION_ROLE));
    }

    private static byte[] derive(KeyVault vault, int identityIndex, int role) {
        int algorithm = new AlgField(AlgField.ALG_ED25519, 0, role).toIndex() | H;
        int[] path = {PURPOSE, OPENPGP, identityIndex, algorithm, CONFIG};
        VaultResult result = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        if (!result.isOk()) {
            throw new IllegalStateException(
                    "KeyVault seed export failed for OpenPGP role " + role + ": " + result.status());
        }
        return result.data();
    }
}

