package com.dragon.crypto;

import com.dragon.crypto.Assert;
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

    private static final int CYCLE_TIMES = 1000;

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
    public byte[] decrypt(CryptoParam param) {
        return crypt(param, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] encrypt(CryptoParam param) {
        return crypt(param, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return crypt(CryptoParam.builder().data(data).build(), Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return crypt(CryptoParam.builder().data(data).build(), Cipher.ENCRYPT_MODE);
    }

    private byte[] crypt(CryptoParam param, int mode) {
        byte[] data = param.getData();
        Assert.notEmpty(data, "data is null or empty");
        setDefault(param);
        PBEParameterSpec paramSpec = new PBEParameterSpec(param.getSalt().getBytes(), CYCLE_TIMES);
        try {
            Cipher cipher = Cipher.getInstance(current().getCode());
            cipher.init(mode, toKey(param.getKey()), paramSpec);
            return cipher.doFinal(param.getData());
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private CryptoParam setDefault(CryptoParam param) {
        param.setKey(Utils.isBlank(param.getKey()) ? DEFAULT_KEY : param.getKey());
        String salt = Utils.isBlank(param.getSalt()) ? DEFAULT_SALT_8 : param.getSalt();
        if (salt.length() != SALT_SIZE) {
            throw new CryptoException("the salt size must be " + SALT_SIZE);
        }
        param.setSalt(salt);
        return param;
    }
}
