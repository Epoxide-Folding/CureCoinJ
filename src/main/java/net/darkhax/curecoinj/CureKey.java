package net.darkhax.curecoinj;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map.Entry;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * This class represents a key pair for a CureCoin address. Constructing a new instance of this
 * class will create a new random key pair.
 */
public class CureKey {

    /**
     * A SECP256K1 key pair generator that is used to generate new random keys.
     */
    private static final ECKeyPairGenerator GENERATOR = Utils.getKeyPairGenerator(Utils.SECP256K1);

    /**
     * The private key value.
     */
    private final BigInteger privateValue;

    /**
     * Whether or not the key address is compressed.
     */
    private final boolean compressed;

    /**
     * Constructs a new key pair. This key pair will not be compressed.
     */
    public CureKey () {

        this(false);
    }

    /**
     * Constructs a new key pair for a CureCoin wallet.
     *
     * @param compressed Whether or not this key is compressed.
     */
    public CureKey (boolean compressed) {

        this.compressed = compressed;
        final Entry<ECPublicKeyParameters, ECPrivateKeyParameters> keypair = Utils.getNewKeyPair(GENERATOR);
        this.privateValue = keypair.getValue().getD();
    }

    /**
     * Gets the original private key value.
     *
     * @return The private key value.
     */
    public BigInteger getPrivateKey () {

        return this.privateValue;
    }

    /**
     * Gets the private key in a usable wallet import format base58 string.
     *
     * @return
     */
    public String getWalletImportKey () {

        return Base58.encode(this.getWalletImportKeyBytes());
    }

    /**
     * Gets an array of bytes which represent the private key in the wallet import format.
     * Including the 0x99 identifier byte, the compression byte and the checksum bytes.
     *
     * @return An array of bytes that represent the private wallet import format key.
     */
    public byte[] getWalletImportKeyBytes () {

        byte[] data = this.getPrivateKey().toByteArray();

        // Trim input array to 32 bytes
        data = Arrays.copyOfRange(data, 0, 32);

        // Prepend 0x99 byte
        data = Utils.prependBytes(data, (byte) 0x99);

        // Add compressed byte if compressed
        if (this.compressed) {

            data = Utils.appendBytes(data, (byte) 0x01);
        }

        // Append first 4 bytes of checksum
        data = Utils.appendBytes(data, Utils.getChecksum(data));

        return data;

    }

    /**
     * Gets the public key as a usable base58 encoded string.
     *
     * @return The public key for this key pair.
     */
    public String getPublicKey () {

        return Base58.encode(this.getPublicKeyBytes());
    }

    /**
     * Gets the public key bytes for the key pair. The output has the 0x19 identifying byte and
     * the checksum bytes added on so it can be usable by wallets.
     *
     * @return The public key bytes.
     */
    public byte[] getPublicKeyBytes () {

        // Get the public key hash bytes.
        byte[] publicBytes = this.getPublicHash();

        // Prepends the public bytes with the 0x19 (B) byte.
        publicBytes = Utils.prependBytes(publicBytes, (byte) 0x19);

        // Adds four checksum bytes to the public key bytes
        publicBytes = Utils.concatBytes(publicBytes, Utils.getChecksum(publicBytes));

        return publicBytes;
    }

    /**
     * Gets an array of bytes that represent the public key. The public key is derived from the
     * private key and ran through a sha256 and ripemd160 algorithm.
     *
     * @return An array of bytes that represent the public key.
     */
    public byte[] getPublicHash () {

        return Utils.sha256AndRipe160(Utils.SECP256K1.getG().multiply(this.privateValue).getEncoded(this.compressed));
    }

    /**
     * Checks if the CureKey pair is compressed or not.
     *
     * @return Whether or not this key pair is compressed.
     */
    public boolean getCompressed () {

        return this.compressed;
    }
}