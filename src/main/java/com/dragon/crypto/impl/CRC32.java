package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.Crypto;
import com.dragon.crypto.CryptoParam;
import com.dragon.crypto.Assert;
import com.dragon.crypto.builder.BasicBuilder;

/**
 * @ClassName: CRC32
 * @Description: CRC32
 * @Author: pengl
 * @Date: 2020/3/28 10:55
 * @Version V1.0
 */
public class CRC32 implements Crypto {

    @Override
    public byte[] encrypt(BasicBuilder builder) {
        byte[] data = builder.getData();
        Assert.notEmpty(data, "data is null or empty");
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);
        return Long.toHexString(crc32.getValue()).getBytes();
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(new BasicBuilder().data(data));
    }

    @Override
    public Algorithm current() {
        return Algorithm.CRC32;
    }
}
