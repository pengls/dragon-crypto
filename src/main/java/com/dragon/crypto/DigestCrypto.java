package com.dragon.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName: DigestCrypto
 * @Description: 消息摘要算法
 * @Author: pengl
 * @Date: 2020/3/28 15:36
 * @Version V1.0
 */
public abstract class DigestCrypto implements Crypto{

    @Override
    public byte[] encrypt(CryptoParam param) {
        byte[] data = param.getData();
        Assert.notEmpty(data, "data is null or empty");
        return getMessageDigest(current()).digest(data);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(CryptoParam.builder().data(data).build());
    }

    /**
     * @MethodName: getMessageDigest
     * @Description: jdk MessageDigest
     * @Author: pengl
     * @Date: 2020/3/27 21:19
     * @Version V1.0
     */
    private MessageDigest getMessageDigest(Algorithm algorithm) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getCode());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        return messageDigest;
    }
}
