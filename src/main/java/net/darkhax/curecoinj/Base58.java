/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This class is taken from BitcoinJ-Minimal which is a fork of BitcoinJ
 * https://github.com/bitcoin-labs/bitcoinj-minimal/blob/master/core/Base58.java
 * https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/Base58.java
 *
 * Changes:   - Removed decodeChecked because this class does not normally handle checksum bytes.
 *            - Renamed decode to decodeToBytes.
 *            - Renamed decodeToBigInteger to decode, as it's what does the actual decoding.
 *            - Renamed ALPHABET to ALPANUMERIC_LEGEND.
 *            - Replaced AddressFormatException with IllegalArgumentException.
 *            - Replaced System.arraycopy with Arrays.copyOfRange.
 *            - Removed leading 0 check in encode/decode process.
 *            - Many effectively final variables were marked final.
 *            - Many constant and variable names were changed to be more descriptive.
 *            - All comments and documentation were rewritten.
 */
package net.darkhax.curecoinj;

import java.math.BigInteger;

/**
 * This class contains static methods for encoding and decoding data in base58. This
 * implementation was written with cryptocurrencies in mind.
 *
 * Base58 is used by many cryptocurrencies because it is fairly simple to understand. The
 * resulting strings are also easier for humans and web/email clients to work with than formats
 * that include non alphanumeric characters.
 */
public class Base58 {

    /**
     * A legend that is used to encode and decode data. This legend has 58 characters. The
     * ordering of these characters determines how encoded and decoded data is handled. The
     * ordering used in this implementation is valid for cryptocurrencies like Bitcoin,
     * Peercoin, and CureCoin. This is not the same legend used by Ripple or Flickr.
     */
    private static final String ALPHANUMERIC_LEGEND = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /**
     * A constant reference to the base value 58. It is used in encoding and decoding data.
     */
    private static final BigInteger BASE = BigInteger.valueOf(58);

    /**
     * Encodes an array of bytes into a string that can be decoded using base58.
     *
     * NOTE: Traditionally this process involves checking the input data for leading 0s. This
     * implementation was written with CureCoin in mind, and it is not possible for a valid
     * address to have leading 0 bytes. For this reason that check was omitted. If issues with
     * the come up, it is recommended that they are reported or a different Base58
     * implementation is used instead.
     *
     * @param input The input bytes to encode.
     * @return A base58 string that can be decoded using {@link #decode(String)} and
     *         {@link #decodeToBytes(String)} or other means of decoding base58 strings.
     */
    public static String encode (byte[] input) {

        BigInteger toEncode = new BigInteger(1, input);

        final StringBuffer buffer = new StringBuffer();

        // While the encoded integer is greater than or equal to 58
        while (toEncode.compareTo(BASE) >= 0) {

            final BigInteger mod = toEncode.mod(BASE);
            buffer.insert(0, ALPHANUMERIC_LEGEND.charAt(mod.intValue()));
            toEncode = toEncode.subtract(mod).divide(BASE);
        }

        buffer.insert(0, ALPHANUMERIC_LEGEND.charAt(toEncode.intValue()));

        return buffer.toString();
    }

    /**
     * Decodes a base58 string to a byte array. A valid input string can only contain 1->9,
     * a->z, and A->Z. Unlike {@link #decode(String)} this method will automatically detect and
     * discard the signed byte.
     *
     * NOTE: Traditionally this process involves checking the data for leading 0s. This
     * implementation was written with CureCoin in mind, and it is not possible for a valid
     * address to have leading 0 bytes. For this reason that check was omitted. If issues with
     * the come up, it is recommended that they are reported or a different Base58
     * implementation is used instead.
     *
     * @param input The string to decode.
     * @return An array of bytes that represent the encoded data.
     * @throws IllegalArgumentException If the input string contains an invalid character.
     */
    public static byte[] decodeToBytes (String input) throws IllegalArgumentException {

        final byte[] decodedBytes = decode(input).toByteArray();

        // The decoded BigInteger is likely signed. If it is, the signed byte is stripped.
        return Utils.isSigned(decodedBytes) ? Utils.removeSignedByte(decodedBytes) : decodedBytes;
    }

    /**
     * Decodes a base58 string to a BigInteger. A valid input string can only contain 1->9,
     * a->z, and A->Z. Please note that the resulting BigInteger will likely contain an
     * additional byte at the start. This byte is added by Java when the integer is signed. If
     * present, it is safe to remove.
     *
     * @param input The string to decode.
     * @return A BigInteger that contains the decoded bytes of the input string.
     * @throws IllegalArgumentException If the input string contains an invalid character.
     */
    public static BigInteger decode (String input) throws IllegalArgumentException {

        BigInteger decoded = BigInteger.valueOf(0);

        for (int index = input.length() - 1; index >= 0; index--) {

            // Gets the index of the current character in alphanumeric legend
            final int legendIndex = ALPHANUMERIC_LEGEND.indexOf(input.charAt(index));

            // If the character is not in the valid characters legend the string is invalid.
            if (legendIndex == -1) {

                throw new IllegalArgumentException("Invalid character " + input.charAt(index) + " at " + index + ". Must be alphanumeric.");
            }

            // Adds the value of the character to the decoded value.
            decoded = decoded.add(BigInteger.valueOf(legendIndex).multiply(BASE.pow(input.length() - 1 - index)));
        }

        return decoded;
    }
}