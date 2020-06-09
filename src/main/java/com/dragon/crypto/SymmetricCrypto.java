package com.dragon.crypto;

import com.dragon.crypto.builder.BasicBuilder;
import com.dragon.crypto.builder.PBEBuilder;
import com.dragon.crypto.builder.SymmetricBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * @ClassName: SymmetricCrypto
 * @Description: 对称加密
 * @Author: pengl
 * @Date: 2020/3/28 15:44
 * @Version V1.0
 */
public abstract class SymmetricCrypto implements Crypto {
    /**
     * default key, size:24 (DES)
     */
    protected static final String DEFAULT_KEY_24 = "~!@#$%^&*()_+QWERTabcGBN";
    /**
     * default key, size:32 (AES)
     */
    protected static final String DEFAULT_KEY_32 = "1ph~!@#$%^&*(+QBNb*&^)$%#sp75gqp";
    /**
     * default iv, size:8 (DES-CBC)
     */
    protected static final String DEFAULT_IV_8 = ")(*&*^%@";
    /**
     * default iv, size:16 (AES-CBC)
     */
    protected static final String DEFAULT_IV_16 = "ij018395)(*&*^%@";
    /**
     * default padding
     */
    protected static final CryptoParam.Padding DEFAULT_PADDING = CryptoParam.Padding.PKCS5Padding;
    /**
     * default work model
     */
    protected static final CryptoParam.WorkModel DEFAULT_WORK_MODEL = CryptoParam.WorkModel.ECB;
    /**
     * Separator
     */
    protected static final String CIPHER_SEPARATOR = "/";

    protected static final int TAG_LEN = 16;

    protected static final int MIN_KEY_SIZE_DES = 8;
    protected static final int MIN_KEY_SIZE_DES3 = 24;
    protected static final int MIN_IV_SIZE_AES = 16;
    protected static final int MIN_IV_SIZE_DES = 8;

    @Override
    public byte[] decrypt(byte[] data) {
        return crypt(new SymmetricBuilder().data(data), 2);
    }


    @Override
    public byte[] encrypt(byte[] data) {
        return crypt(new SymmetricBuilder().data(data), 1);
    }


    @Override
    public byte[] decrypt(BasicBuilder builder) {
        return crypt(builder, 2);
    }


    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return crypt(builder, 1);
    }

    private byte[] crypt(BasicBuilder builder, int type) {
        Assert.isInstanceOf(SymmetricBuilder.class, builder, "please use SymmetricBuilder build params.");
        SymmetricBuilder symmetricBuilder = (SymmetricBuilder) builder;
        byte[] data = symmetricBuilder.getData();
        Assert.notEmpty(data, "data is null or empty");
        String key = Utils.isBlank(symmetricBuilder.getKey()) ? (Algorithm.AES == current() ? DEFAULT_KEY_32 : DEFAULT_KEY_24) : symmetricBuilder.getKey();
        symmetricBuilder.setKey(key);

        String iv = Utils.isBlank(symmetricBuilder.getIv()) ? (Algorithm.AES == current() ? DEFAULT_IV_16 : DEFAULT_IV_8) : symmetricBuilder.getIv();
        symmetricBuilder.setIv(iv);

        return type == 1 ? encry(symmetricBuilder) : decry(symmetricBuilder);
    }

    private byte[] encry(SymmetricBuilder symmetricBuilder) {
        try {
            Cipher cipher = Cipher.getInstance(current().getCode() + CIPHER_SEPARATOR + symmetricBuilder.getWorkModel() + CIPHER_SEPARATOR + symmetricBuilder.getPadding());
            initCipher(cipher, Cipher.ENCRYPT_MODE, symmetricBuilder);
            return cipher.doFinal(symmetricBuilder.getData());
        } catch (Exception e) {
            e.printStackTrace();
            throw new CryptoException(e.getMessage());
        }
    }

    private byte[] decry(SymmetricBuilder symmetricBuilder) {
        try {
            Cipher cipher = Cipher.getInstance(current().getCode() + CIPHER_SEPARATOR + symmetricBuilder.getWorkModel() + CIPHER_SEPARATOR + symmetricBuilder.getPadding());
            initCipher(cipher, Cipher.DECRYPT_MODE, symmetricBuilder);
            return cipher.doFinal(symmetricBuilder.getData());
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private void initCipher(Cipher cipher, int model, SymmetricBuilder symmetricBuilder) throws InvalidKeyException, InvalidAlgorithmParameterException {

        byte[] key = CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(symmetricBuilder.getKey().getBytes(DEFAULT_CHARSET));
        byte[] iv = CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(symmetricBuilder.getIv().getBytes(DEFAULT_CHARSET));
        Algorithm curAlg = current();

        byte[] subKey;
        if (Algorithm.DES3 == curAlg) {
            subKey = new byte[MIN_KEY_SIZE_DES3];
            System.arraycopy(key, 0, subKey, 0, MIN_KEY_SIZE_DES3);
        } else if (Algorithm.DES == curAlg) {
            subKey = new byte[MIN_KEY_SIZE_DES];
            System.arraycopy(key, 0, subKey, 0, MIN_KEY_SIZE_DES);
        } else if (Algorithm.AES == curAlg) {
            subKey = key;
        } else {
            subKey = key;
        }

        byte[] subIv;
        if (Algorithm.DES == current() || Algorithm.DES3 == current()) {
            subIv = new byte[MIN_IV_SIZE_DES];
            System.arraycopy(iv, 0, subIv, 0, MIN_IV_SIZE_DES);
        } else if (Algorithm.AES == curAlg) {
            subIv = new byte[MIN_IV_SIZE_AES];
            System.arraycopy(iv, 0, subIv, 0, MIN_IV_SIZE_AES);
        } else {
            subIv = iv;
        }

        if (SymmetricBuilder.WorkModel.ECB == symmetricBuilder.getWorkModel()) {
            cipher.init(model, toKey(subKey));
        } else if (SymmetricBuilder.WorkModel.GCM == symmetricBuilder.getWorkModel()) {
            GCMParameterSpec gcmPs = new GCMParameterSpec(TAG_LEN * Byte.SIZE, subIv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(subKey, current().getCode());
            cipher.init(model, secretKeySpec, gcmPs);
            cipher.updateAAD(subKey);
        } else {
            IvParameterSpec ips = new IvParameterSpec(subIv);
            cipher.init(model, toKey(subKey), ips);
        }
    }

}
