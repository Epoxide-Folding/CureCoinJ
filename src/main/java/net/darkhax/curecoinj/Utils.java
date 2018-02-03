package net.darkhax.curecoinj;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Map.Entry;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.FixedPointUtil;

/**
 * This class contains a bunch of static helper and utility methods for working with
 * cryptography and modifying byte arrays.
 */
public final class Utils {

    /**
     * A constant reference to the SHA256 implementation.
     */
    public static final MessageDigest SHA256;

    /**
     * A constant reference to Bouncy Castle's RIPEMD160 implementation.
     */
    public static final MessageDigest RIPEMD160;

    /**
     * Elliptic Curve parameters for SECP256k1.
     */
    public static final ECDomainParameters SECP256K1;

    /**
     * A constant reference to a reusable SecureRandom object.
     */
    public static final SecureRandom SECURE_RANDOM;

    static {

        // This provider is required to use RIPEMD160
        Security.addProvider(new BouncyCastleProvider());

        // Setting constants after provider has been added to be safe.
        SHA256 = getMessageDigest("SHA-256");
        RIPEMD160 = getMessageDigest("RIPEMD160");
        SECP256K1 = getCurveParams("secp256k1");

        // Hopefully secure
        SECURE_RANDOM = new SecureRandom();
    }

    /**
     * Checks if an array of bytes represents a signed integer.
     *
     * @param bytes The byte array to check.
     * @return Whether or not the byte array represents a signed integer.
     */
    public static boolean isSigned (byte[] bytes) {

        return bytes.length > 1 && bytes[0] == 0 && bytes[1] < 0;
    }

    /**
     * Checks if an array of bytes represents a signed integer, and removes the signed byte if
     * it does.
     *
     * @param bytes The byte array to check.
     * @return The modified array of bytes. If the byte array was not signed, it will not be
     *         modified.
     */
    public static byte[] removeSignedByte (byte[] bytes) {

        return isSigned(bytes) ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    /**
     * Gets an elliptic curve key pair generator for elliptic curve parameters.
     *
     * @param params The parameters to get a key pair generator for.
     * @return A new key pair generator based on the elliptic curve parameters.
     */
    public static ECKeyPairGenerator getKeyPairGenerator (ECDomainParameters params) {

        final ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(params, SECURE_RANDOM));
        return generator;
    }

    /**
     * Gets a new key pair from an elliptic curve key pair generator.
     *
     * @param generator The generator to generate a new key with.
     * @return A map entry that contains a public and private key.
     */
    public static Entry<ECPublicKeyParameters, ECPrivateKeyParameters> getNewKeyPair (ECKeyPairGenerator generator) {

        final AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        return new SimpleImmutableEntry<>((ECPublicKeyParameters) keypair.getPublic(), (ECPrivateKeyParameters) keypair.getPrivate());
    }

    /**
     * Gets elliptic curve parameters based on the name of the curve.
     *
     * @param name The name of the curve you want.
     * @return The elliptic curve parameters of the target curve.
     */
    public static ECDomainParameters getCurveParams (String name) {

        final X9ECParameters params = SECNamedCurves.getByName(name);
        FixedPointUtil.precompute(params.getG());
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    /**
     * Runs an array of bytes through the sha256 algorithm, and then runs the results of the
     * first run through the sha256 algorithm again.
     *
     * @param data The data bytes to double digest.
     * @return The double hashed bytes.
     */
    public static byte[] doubleSha256 (byte[] data) {

        return SHA256.digest(SHA256.digest(data));
    }

    /**
     * Runs an array of bytes through the sha256 algorithm, and then runs the results of the
     * first run through a RipeMd160 algorithm.
     *
     * @param data The data bytes to digest.
     * @return The hashed bytes.
     */
    public static byte[] sha256AndRipe160 (byte[] data) {

        return RIPEMD160.digest(SHA256.digest(data));
    }

    /**
     * Adds some bytes to the start of a byte array.
     *
     * @param initial The initial byte array.
     * @param toPrepend The bytes to insert at the start of the array.
     * @return The prepended byte array.
     */
    public static byte[] prependBytes (byte[] initial, byte... toPrepend) {

        return concatBytes(toPrepend, initial);
    }

    /**
     * Adds some bytes to the end of a byte array.
     *
     * @param initial The initial byte array.
     * @param toAppend The bytes to insert at the end of the array.
     * @return The appened byte array.
     */
    public static byte[] appendBytes (byte[] initial, byte... toAppend) {

        return concatBytes(initial, toAppend);
    }

    /**
     * Join two arrays into a new array.
     *
     * @param a The first array, this will occupy the start of the new array.
     * @param b The second array, this will occupy the end of the new array.
     * @return A joined version of the two initial arrays.
     */
    public static byte[] concatBytes (byte[] a, byte[] b) {

        final byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Gets a MessageDigest safely. If there is no digest with the passed name it will print an
     * exception and return null.
     *
     * @param name The name of the digest to get.
     * @return The MessageDigest associated with the passed name.
     */
    public static MessageDigest getMessageDigest (String name) {

        try {

            return MessageDigest.getInstance(name);
        }

        catch (final NoSuchAlgorithmException e) {

            e.printStackTrace();
        }

        return null;
    }

    /**
     * Isolates the checksum bytes from the data bytes. In Base58 the last four bytes are used
     * as a checksum, all other bytes represent the data that was encoded. The checksum bytes
     * are added during the encoding process and serve as a fingerprint that can be used to
     * verify the integrity of the data.
     *
     * @param input The byte array to retrieve the checksum bytes from.
     * @return An array of bytes that represent the intended checksum for the input. This
     *         should be an array of four bytes.
     */
    public static byte[] getDecodedChecksum (byte[] input) {

        return Arrays.copyOfRange(input, input.length - 4, input.length);
    }

    /**
     * Isolates the data bytes from the checksum bytes. In Base58 the last four bytes are used
     * as a checksum.
     *
     * @param input The byte array to retrieve the data bytes from.
     * @return An array of bytes that only contains the encoded data and not the checksum
     *         bytes.
     */
    public static byte[] getDataBytes (byte[] input) {

        return Arrays.copyOfRange(input, 0, input.length - 4);
    }

    /**
     * Gets the checksum bytes of an input byte array. This is done by hashing the input with
     * SHA256, and then hashing the result with SHA256 again. The first four bytes of the
     * double hashed data is used as the checksum value. The checksum bytes serve as a
     * fingerprint that can be used to ensure the integrity of the data.
     *
     * @param input The byte array to get a checksum for.
     * @return An array of bytes that can be used as a checksum. This should be an array of
     *         four bytes.
     */
    public static byte[] getChecksum (byte[] input) {

        return Arrays.copyOfRange(Utils.doubleSha256(input), 0, 4);
    }
}
