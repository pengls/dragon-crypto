package com.dragon.crypto;

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
        return crypt(CryptoParam.builder().data(data).build(), 2);
    }


    @Override
    public byte[] encrypt(byte[] data) {
        return crypt(CryptoParam.builder().data(data).build(), 1);
    }


    @Override
    public byte[] decrypt(CryptoParam param) {
        return crypt(param, 2);
    }


    @Override
    public byte[] encrypt(CryptoParam param) {
        return crypt(param, 1);
    }

    private byte[] crypt(CryptoParam param, int type) {
        byte[] data = param.getData();
        Assert.notEmpty(data, "data is null or empty");
        String key = Utils.isBlank(param.getKey()) ? (Algorithm.AES == current() ? DEFAULT_KEY_32 : DEFAULT_KEY_24) : param.getKey();
        param.setKey(key);

        String iv = Utils.isBlank(param.getIv()) ? (Algorithm.AES == current() ? DEFAULT_IV_16 : DEFAULT_IV_8) : param.getIv();
        param.setIv(iv);

        return type == 1 ? encry(param) : decry(param);
    }

    private byte[] encry(CryptoParam param) {
        try {
            Cipher cipher = Cipher.getInstance(current().getCode() + CIPHER_SEPARATOR + param.getWorkModel() + CIPHER_SEPARATOR + param.getPadding());
            initCipher(cipher, Cipher.ENCRYPT_MODE, param);
            return cipher.doFinal(param.getData());
        } catch (Exception e) {
            e.printStackTrace();
            throw new CryptoException(e.getMessage());
        }
    }

    private byte[] decry(CryptoParam param) {
        try {
            Cipher cipher = Cipher.getInstance(current().getCode() + CIPHER_SEPARATOR + param.getWorkModel() + CIPHER_SEPARATOR + param.getPadding());
            initCipher(cipher, Cipher.DECRYPT_MODE, param);
            return cipher.doFinal(param.getData());
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private void initCipher(Cipher cipher, int model, CryptoParam param) throws InvalidKeyException, InvalidAlgorithmParameterException {

        byte[] key = CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(param.getKey().getBytes(DEFAULT_CHARSET));
        byte[] iv = CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(param.getIv().getBytes(DEFAULT_CHARSET));
        Algorithm curAlg = current();

        byte[] subKey;
        if (Algorithm.DES3 == curAlg) {
            subKey = new byte[MIN_KEY_SIZE_DES3];
            System.arraycopy(key, 0, subKey, 0, MIN_KEY_SIZE_DES3);
        }else if (Algorithm.DES == curAlg) {
            subKey = new byte[MIN_KEY_SIZE_DES];
            System.arraycopy(key, 0, subKey, 0, MIN_KEY_SIZE_DES);
        }else if (Algorithm.AES == curAlg) {
            subKey = key;
        }else{
            subKey = key;
        }

        byte[] subIv;
        if (Algorithm.DES == current() || Algorithm.DES3 == current()) {
            subIv = new byte[MIN_IV_SIZE_DES];
            System.arraycopy(iv, 0, subIv, 0, MIN_IV_SIZE_DES);
        }else if (Algorithm.AES == curAlg) {
            subIv = new byte[MIN_IV_SIZE_AES];
            System.arraycopy(iv, 0, subIv, 0, MIN_IV_SIZE_AES);
        }else{
            subIv = iv;
        }

        if (CryptoParam.WorkModel.ECB == param.getWorkModel()) {
            cipher.init(model, toKey(subKey));
        } else if (CryptoParam.WorkModel.GCM == param.getWorkModel()) {
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
