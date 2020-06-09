package com.dragon.crypto;

import com.dragon.crypto.Assert;
import com.dragon.crypto.builder.BasicBuilder;
import com.dragon.crypto.builder.PBEBuilder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * @ClassName: PBECrypto
 * @Description: 带口令(salt)的整合对称算法
 * @Author: pengl
 * @Date: 2020/3/28 16:48
 * @Version V1.0
 */
public abstract class PBECrypto implements Crypto {
    /**
     * default salt, size:8 (PBEWithMd5AndDes)
     */
    protected static final String DEFAULT_SALT_8 = "ks*&%$)1";

    private static final int SALT_SIZE = 8;

    private static final int DEFAULT_CYCLE_TIMES = 1000;

    @Override
    public SecretKey toKey(final String key) {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(key.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(current().getCode());
            return keyFactory.generateSecret(pbeKeySpec);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    @Override
    public byte[] decrypt(BasicBuilder builder) {
        return crypt(builder, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return crypt(builder, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return crypt(new PBEBuilder().data(data), Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return crypt(new PBEBuilder().data(data), Cipher.ENCRYPT_MODE);
    }

    private byte[] crypt(BasicBuilder builder, int mode) {
        Assert.isInstanceOf(PBECrypto.class, builder, "please use PBEBuilder build params.");
        PBEBuilder pbeBuilder = (PBEBuilder) builder;
        byte[] data = builder.getData();
        Assert.notEmpty(data, "data is null or empty");
        setDefault(pbeBuilder);
        PBEParameterSpec paramSpec = new PBEParameterSpec(pbeBuilder.getSalt().getBytes(), pbeBuilder.getCycleTimes());
        try {
            Cipher cipher = Cipher.getInstance(current().getCode());
            cipher.init(mode, toKey(pbeBuilder.getKey()), paramSpec);
            return cipher.doFinal(pbeBuilder.getData());
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private PBEBuilder setDefault(PBEBuilder builder) {
        builder.setKey(Utils.isBlank(builder.getKey()) ? DEFAULT_KEY : builder.getKey());
        builder.setCycleTimes(builder.getCycleTimes() == 0 ? DEFAULT_CYCLE_TIMES : builder.getCycleTimes());
        String salt = Utils.isBlank(builder.getSalt()) ? DEFAULT_SALT_8 : builder.getSalt();
        if (salt.length() != SALT_SIZE) {
            throw new CryptoException("the salt size must be " + SALT_SIZE);
        }
        builder.setSalt(salt);
        return builder;
    }
}
