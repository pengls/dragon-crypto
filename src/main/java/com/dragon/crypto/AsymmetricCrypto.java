package com.dragon.crypto;

import com.dragon.crypto.Assert;
import com.dragon.crypto.builder.AsymmetricBuilder;
import com.dragon.crypto.builder.BasicBuilder;
import com.dragon.crypto.builder.SymmetricBuilder;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @ClassName: AsymmetricCrypto
 * @Description: 非对称加密
 * @Author: pengl
 * @Date: 2020/3/29 13:10
 * @Version V1.0
 */
public abstract class AsymmetricCrypto implements Crypto {
    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return encry(builder);
    }

    @Override
    public byte[] decrypt(BasicBuilder builder) {
        return decry(builder);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(new AsymmetricBuilder().data(data));
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return decrypt(new AsymmetricBuilder().data(data));
    }

    private byte[] decry(BasicBuilder builder) {
        Assert.isInstanceOf(AsymmetricBuilder.class, builder, "please use AsymmetricBuilder build params.");
        AsymmetricBuilder asymmetricBuilder = (AsymmetricBuilder) builder;
        byte[] data = asymmetricBuilder.getData();
        Assert.notEmpty(data, "data is null or empty");
        checkKey(asymmetricBuilder);
        if (Utils.isNotBlank(asymmetricBuilder.getPublicKey())) {
            return decryptByPublicKey(asymmetricBuilder.getData(), Base64.decodeBase64(asymmetricBuilder.getPublicKey()));
        }
        if (Utils.isNotBlank(asymmetricBuilder.getPrivateKey())) {
            return decryptByPrivateKey(asymmetricBuilder.getData(), Base64.decodeBase64(asymmetricBuilder.getPrivateKey()));
        }
        return null;
    }

    private void checkKey(AsymmetricBuilder asymmetricBuilder) {
        if (Utils.isAllBlank(asymmetricBuilder.getPrivateKey(), asymmetricBuilder.getPublicKey())) {
            throw new CryptoException("the key(private or public) must not be null !");
        }
    }

    private byte[] encry(BasicBuilder builder) {
        Assert.isInstanceOf(AsymmetricBuilder.class, builder, "please use AsymmetricBuilder build params.");
        AsymmetricBuilder asymmetricBuilder = (AsymmetricBuilder) builder;
        byte[] data = asymmetricBuilder.getData();
        Assert.notEmpty(data, "data is null or empty");
        if (Utils.isNotBlank(asymmetricBuilder.getPublicKey())) {
            return encryptByPublicKey(asymmetricBuilder.getData(), Base64.decodeBase64(asymmetricBuilder.getPublicKey()));
        }
        if (Utils.isNotBlank(asymmetricBuilder.getPrivateKey())) {
            return encryptByPrivateKey(asymmetricBuilder.getData(), Base64.decodeBase64(asymmetricBuilder.getPrivateKey()));
        }
        return null;
    }

    /**
     * @MethodName: decryptByPrivateKey
     * @Description: decrypt by private key
     * @Author: pengl
     * @Date: 2020/3/28 20:24
     * @Version V1.0
     */
    public byte[] decryptByPrivateKey(byte[] data, byte[] key) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(current().getCode());
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /**
     * @MethodName: decryptByPublicKey
     * @Description: decrypt by public key
     * @Author: pengl
     * @Date: 2020/3/28 20:24
     * @Version V1.0
     */
    public byte[] decryptByPublicKey(byte[] data, byte[] key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(current().getCode());
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /**
     * @MethodName: encryptByPublicKey
     * @Description: encrypt by public key
     * @Author: pengl
     * @Date: 2020/3/28 20:24
     * @Version V1.0
     */
    public byte[] encryptByPublicKey(byte[] data, byte[] key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(current().getCode());
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /**
     * @MethodName: encryptByPrivateKey
     * @Description: encrypt by private key
     * @Author: pengl
     * @Date: 2020/3/28 20:24
     * @Version V1.0
     */
    public byte[] encryptByPrivateKey(byte[] data, byte[] key) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(current().getCode());
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }
}
