package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.Crypto;
import com.dragon.crypto.builder.BasicBuilder;

/**
 * @ClassName: Base64
 * @Description: base64 base on common-codec
 * @Author: pengl
 * @Date: 2020/3/27 21:11
 * @Version V1.0
 */
public class Base64 implements Crypto {
    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(builder.getData());
    }

    @Override
    public byte[] decrypt(BasicBuilder builder) {
        return org.apache.commons.codec.binary.Base64.decodeBase64(builder.getData());
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(data);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return org.apache.commons.codec.binary.Base64.decodeBase64(data);
    }


    @Override
    public Algorithm current() {
        return Algorithm.Base64;
    }
}
