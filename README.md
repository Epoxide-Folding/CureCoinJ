# CureCoinJ
This library aims to allow interaction and implementation of CureCoin into Java applications. 

# WARNING
A bug with public keys has been observed using older versions of Java. This bug causes incorrect public keys to be generated by the library. Please ensure that you are using Java 151 or newer.

# How to use?
New CureCoin key pairs can be created by constructing a new CureKey object. Each key pair is a new object. 

```java
        final CureKey key = new CureKey(true);
        System.out.println("Pub: " + key.getPublicKey());
        System.out.println("Priv: " + key.getWalletImportKey());
```

# Maven
This library is not currently on Maven. 