package club.dwdc.keyexporter.core;

public record OpenPgpKeySeeds(byte[] certification, byte[] signing, byte[] encryption) {
    public OpenPgpKeySeeds {
        certification = requireSeed(certification, "certification");
        signing = requireSeed(signing, "signing");
        encryption = requireSeed(encryption, "encryption");
    }

    private static byte[] requireSeed(byte[] seed, String name) {
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException(name + " seed must be 32 bytes");
        }
        return seed.clone();
    }

    @Override
    public byte[] certification() {
        return certification.clone();
    }

    @Override
    public byte[] signing() {
        return signing.clone();
    }

    @Override
    public byte[] encryption() {
        return encryption.clone();
    }
}

