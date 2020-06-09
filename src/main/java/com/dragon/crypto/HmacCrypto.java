package com.dragon.crypto;

import com.dragon.crypto.builder.BasicBuilder;

import javax.crypto.Mac;
/**
 * @ClassName: HmacCrypto
 * @Description: 带密钥的消息摘要算法
 * @Author: pengl
 * @Date: 2020/3/28 15:40
 * @Version V1.0
 */
public abstract class HmacCrypto implements Crypto{

    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return mac(builder);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(new BasicBuilder().data(data));
    }


    private byte[] mac(BasicBuilder builder) {
        byte[] data = builder.getData();
        Assert.notEmpty(data, "data is null or empty");
        String key = Utils.isBlank(builder.getKey()) ? DEFAULT_KEY : builder.getKey();
        try {
            Mac mac = Mac.getInstance(current().getCode());
            mac.init(toKey(key));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }
}
