package com.dragon.crypto;

import com.dragon.crypto.Assert;
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

    //private static final String DEFAULT_PUBLICK_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRSIxHVvhRsxfAv7-96XmeXIMl_ehWYI90KMV3BCGl3uFcr8zBaPTV3OhfE3zhQmG48IyUXV6DUkZYDUPmm6HCFfp--svqw9ju0U3TlzzykIvg5x5yRxrGAbVXQjgWKsbk6xRFzJRq3azHWz0qQ4QodA2SiTY8Y1aeHWqJqVRqeQIDAQAB";
    //private static final String DEFAULT_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANFIjEdW-FGzF8C_v73peZ5cgyX96FZgj3QoxXcEIaXe4VyvzMFo9NXc6F8TfOFCYbjwjJRdXoNSRlgNQ-abocIV-n76y-rD2O7RTdOXPPKQi-DnHnJHGsYBtVdCOBYqxuTrFEXMlGrdrMdbPSpDhCh0DZKJNjxjVp4daompVGp5AgMBAAECgYAL3qZ-IVOiJpsxRm7UkZphPfP-QqFbzMw2FV3luylBZBu6Cwp86bwBKS9QvSU3DXHHcHU4sPb8Ub1FnzL7sFYDNsMTXcDq4P8D74vPbQHTlsbuNSOYXTdTs-qBU24ci2kZq7LeNlBIYcKtr8KmrLyhq3UtLS_AcKFhpvswnt3wNQJBAOwCZcaxz2lfiIrH6pf_DgtzKiOM7qWfk8Pi5yLehdWuysNZT5isuNPqr7spgeg5JUkskPyC-A8d77aRHw5NCPMCQQDjAqCM3AJKKJ3RLnGVktcvlvVu7_kSYoufH_jW3Zg3gNoeDRBuRmqdNefMIdDCGVO-EhGSa_DCkV6w5fqLs1njAkEA58Rm_FxLiniF13wB9mhD-5yKCkVxavauHtUqFQUfuzue5X5Ee3NLQtka4Bsf9tR_uD9q1n8raXUFnm0faWTfXwJAU9bIjL1EazcM8hCBCoisyHqsMkiWaF_UyPP55wD4EqeX5rlUdCW1glJCRXXHr6fC8dOigb0zsegWXKbTHX0jmQJBALVIPQPxJN_oxswZnrRGTAOjkCjKj3D2QAKt71oEqPqYo-76g7vHMX4HrBmU3UyCCNWUm_TBhgcJojJ9krbe6YE";

    @Override
    public byte[] encrypt(CryptoParam param) {
        return encry(param);
    }

    @Override
    public byte[] decrypt(CryptoParam param) {
        return decry(param);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(CryptoParam.builder().data(data).build());
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return decrypt(CryptoParam.builder().data(data).build());
    }

    private byte[] decry(CryptoParam param) {
        byte[] data = param.getData();
        Assert.notEmpty(data, "data is null or empty");
        checkKey(param);
        if (Utils.isNotBlank(param.getPublicKey())) {
            return decryptByPublicKey(param.getData(), Base64.decodeBase64(param.getPublicKey()));
        }
        if (Utils.isNotBlank(param.getPrivateKey())) {
            return decryptByPrivateKey(param.getData(), Base64.decodeBase64(param.getPrivateKey()));
        }
        return null;
    }

    private void checkKey(CryptoParam param) {
        if (Utils.isAllBlank(param.getPrivateKey(), param.getPublicKey())) {
            throw new CryptoException("the key(private or public) must not be null !");
        }
    }

    private byte[] encry(CryptoParam param) {
        byte[] data = param.getData();
        Assert.notEmpty(data, "data is null or empty");
        if (Utils.isNotBlank(param.getPublicKey())) {
            return encryptByPublicKey(param.getData(), Base64.decodeBase64(param.getPublicKey()));
        }
        if (Utils.isNotBlank(param.getPrivateKey())) {
            return encryptByPrivateKey(param.getData(), Base64.decodeBase64(param.getPrivateKey()));
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
