package net.darkhax.curecoinj.tests;

import java.util.Arrays;

import net.darkhax.curecoinj.CureKey;

public class TestOutput {

    // TODO add docs
    // TODO move to proper logger

    // The purpose of this test is to print the current java version, and then dump three
    // randomly generated wallets.
    public static void main (String... strings) {

        System.out.println("Java version is: " + System.getProperty("java.version"));

        System.out.println();

        System.out.println("Now generating three NEW wallets.");
        System.out.println("Please don't try to use these. They are not secure!");
        System.out.println();

        for (int i = 1; i < 4; i++) {

            final CureKey key = new CureKey(true);
            System.out.println("Address #" + i);
            System.out.println("Pub: " + key.getPublicKey());
            System.out.println("Priv: " + key.getWalletImportKey());
            System.out.println("PubHash: " + Arrays.toString(key.getPublicKeyBytes()));
            System.out.println("PrivHash: " + Arrays.toString(key.getWalletImportKeyBytes()));
            System.out.println("");
        }
    }
}
