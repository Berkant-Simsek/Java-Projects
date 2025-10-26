package org.example.algoritmalar.sifreleme;

import org.example.algoritmalar.Algoritmalar;

public abstract class Sifreleme extends Algoritmalar {

    public byte[] inputBytesDecrypt;
    public byte[] inputBytesKey;

    public abstract String generateKeysMessage();
    public abstract byte[] generateKeysFile();
}
