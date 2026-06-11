package club.dwdc.keyexporter.openpgp;

import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HexFormat;

import static org.bouncycastle.openpgp.PGPSignature.POSITIVE_CERTIFICATION;

public final class OpenPgpExporter {
    private OpenPgpExporter() {
    }

    public static OpenPgpExport export(
            OpenPgpKeySeeds seeds, OpenPgpMetadata metadata, char[] secretKeyPassword)
            throws PGPException, IOException {
        if (secretKeyPassword == null || secretKeyPassword.length == 0) {
            throw new IllegalArgumentException("Secret-key password must not be empty");
        }

        Date creationTime = Date.from(metadata.creationTime());
        BcPGPKeyPair primaryPair = ed25519Pair(seeds.certification(), creationTime);
        BcPGPKeyPair signingPair = ed25519Pair(seeds.signing(), creationTime);
        BcPGPKeyPair encryptionPair = x25519Pair(seeds.encryption(), creationTime);

        var digestProvider = new BcPGPDigestCalculatorProvider();
        var sha1 = digestProvider.get(HashAlgorithmTags.SHA1);
        var sha256 = digestProvider.get(HashAlgorithmTags.SHA256);
        var signerBuilder = new BcPGPContentSignerBuilder(
                PublicKeyAlgorithmTags.EDDSA, HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new BcPBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_256, sha256).build(secretKeyPassword);

        var primaryPackets = new org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator();
        primaryPackets.setSignatureCreationTime(false, creationTime);
        primaryPackets.setKeyFlags(false, KeyFlags.CERTIFY_OTHER);
        primaryPackets.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
        });
        primaryPackets.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128
        });
        primaryPackets.setPreferredCompressionAlgorithms(false, new int[]{
                CompressionAlgorithmTags.ZLIB,
                CompressionAlgorithmTags.ZIP,
                CompressionAlgorithmTags.UNCOMPRESSED
        });
        primaryPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPKeyRingGenerator generator = new PGPKeyRingGenerator(
                POSITIVE_CERTIFICATION,
                primaryPair,
                metadata.formattedUserId(),
                sha1,
                primaryPackets.generate(),
                null,
                signerBuilder,
                encryptor);

        var signingPackets = new org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator();
        signingPackets.setSignatureCreationTime(false, creationTime);
        signingPackets.setKeyFlags(false, KeyFlags.SIGN_DATA);
        var backSignaturePackets = new org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator();
        backSignaturePackets.setSignatureCreationTime(false, creationTime);
        PGPSignatureGenerator backSignature = new PGPSignatureGenerator(
                signerBuilder, signingPair.getPublicKey());
        backSignature.init(PGPSignature.PRIMARYKEY_BINDING, signingPair.getPrivateKey());
        backSignature.setHashedSubpackets(backSignaturePackets.generate());
        signingPackets.addEmbeddedSignature(false, backSignature.generateCertification(
                primaryPair.getPublicKey(), signingPair.getPublicKey()));
        generator.addSubKey(signingPair, signingPackets.generate(), null);

        var encryptionPackets = new org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator();
        encryptionPackets.setSignatureCreationTime(false, creationTime);
        encryptionPackets.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        generator.addSubKey(encryptionPair, encryptionPackets.generate(), null);

        PGPSecretKeyRing secretRing = generator.generateSecretKeyRing();
        String publicArmor = armor(output -> secretRing.toCertificate().encode(output));
        String secretArmor = armor(secretRing::encode);
        String fingerprint = HexFormat.of().withUpperCase()
                .formatHex(secretRing.getPublicKey().getFingerprint());
        return new OpenPgpExport(publicArmor, secretArmor, fingerprint);
    }

    private static BcPGPKeyPair ed25519Pair(byte[] seed, Date creationTime) throws PGPException {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(seed, 0);
        AsymmetricCipherKeyPair keyPair =
                new AsymmetricCipherKeyPair(privateKey.generatePublicKey(), privateKey);
        return new BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA, keyPair, creationTime);
    }

    private static BcPGPKeyPair x25519Pair(byte[] seed, Date creationTime) throws PGPException {
        byte[] scalar = seed.clone();
        scalar[0] &= (byte) 0xF8;
        scalar[31] &= (byte) 0x7F;
        scalar[31] |= (byte) 0x40;
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(scalar, 0);
        AsymmetricCipherKeyPair keyPair =
                new AsymmetricCipherKeyPair(privateKey.generatePublicKey(), privateKey);
        return new BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
    }

    private static String armor(Encoder encoder) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ArmoredOutputStream output = new ArmoredOutputStream(buffer)) {
            encoder.encode(output);
        }
        return buffer.toString(StandardCharsets.US_ASCII);
    }

    @FunctionalInterface
    private interface Encoder {
        void encode(ArmoredOutputStream output) throws IOException;
    }
}
