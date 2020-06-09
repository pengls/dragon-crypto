package com.dragon.crypto;

import com.dragon.crypto.builder.AsymmetricBuilder;
import com.dragon.crypto.builder.BasicBuilder;
import com.dragon.crypto.builder.PBEBuilder;
import com.dragon.crypto.builder.SymmetricBuilder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @ClassName: CryptoHelper
 * @Description: 对外提供便于调用的API
 * @Author: pengl
 * @Date: 2020/4/26 21:53
 * @Version V1.0
 */
public final class CryptoHelper {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    //================= base64 =================//
    public static String base64Encode(String data) {
        return Base64.encodeBase64URLSafeString(data.getBytes(DEFAULT_CHARSET));
    }

    public static String base64Decode(String data){
        return StrUtils.newStringUtf8(Base64.decodeBase64(data.getBytes(DEFAULT_CHARSET)));
    }

    //================= 摘要算法 =================//

    public static String md5(String data) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.MD5).encrypt(data.getBytes(DEFAULT_CHARSET)));
    }

    public static String sha256(String data) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(data.getBytes(DEFAULT_CHARSET)));
    }

    public static String sha384(String data) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA384).encrypt(data.getBytes(DEFAULT_CHARSET)));
    }

    public static String sha512(String data) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA512).encrypt(data.getBytes(DEFAULT_CHARSET)));
    }

    //================= 摘要算法 带key =================//

    public static String hmacMD5(String data, String key) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacMD5).encrypt(new BasicBuilder().data(data.getBytes(DEFAULT_CHARSET)).key(key)));
    }

    public static String hmacSHA256(String data, String key) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA256).encrypt(new BasicBuilder().data(data.getBytes(DEFAULT_CHARSET)).key(key)));
    }

    public static String hmacSHA384(String data, String key) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA384).encrypt(new BasicBuilder().data(data.getBytes(DEFAULT_CHARSET)).key(key)));
    }

    public static String hmacSHA512(String data, String key) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA512).encrypt(new BasicBuilder().data(data.getBytes(DEFAULT_CHARSET)).key(key)));
    }

    //================= 摘要算法 带salt =================//

    public static String pbkdf2WithHmacSHA256(String data, String salt) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.PBKDF2WithHmacSHA256).encrypt(new PBEBuilder().data(data.getBytes(DEFAULT_CHARSET)).salt(salt)));
    }

    public static String pbkdf2WithHmacSHA512(String data, String salt) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.PBKDF2WithHmacSHA512).encrypt(new PBEBuilder().data(data.getBytes(DEFAULT_CHARSET)).salt(salt)));
    }

    public static String pbkdf2WithHmacSHA1(String data, String salt) {
        return Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.PBKDF2WithHmacSHA1).encrypt(new PBEBuilder().data(data.getBytes(DEFAULT_CHARSET)).salt(salt)));
    }

    //================= 对称加密/解密 工作模式 向量  填充方式 =================//

    /**
     * 3重DES ：key必须大于等于24位，底层会截取前24个字符做为key；iv:8位
     * AES ：key必须大于等于32位；iv:16位
     * PBE ：基于口令加密，综合des/aes/摘要算法。key必须大于等于32位；salt:8位
     */

    public static String des3Encrypt(String data) {
        return des3Encrypt(data, null, null, null, null);
    }

    public static String des3Decrypt(String data) {
        return des3Decrypt(data, null, null, null, null);
    }

    public static String des3Encrypt(String data, String key) {
        return des3Encrypt(data, key, null, null, null);
    }

    public static String des3Decrypt(String data, String key) {
        return des3Decrypt(data, key, null, null, null);
    }

    public static String des3Encrypt(String data, String key, String iv, SymmetricBuilder.WorkModel workModel, SymmetricBuilder.Padding padding) {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.DES3)
                .encrypt(new SymmetricBuilder()
                        .data(data.getBytes(DEFAULT_CHARSET))
                        .key(key)
                        .iv(iv)
                        .workModel(workModel)
                        .padding(padding)
                        );
        return Base64.encodeBase64URLSafeString(encryt);
    }

    public static String des3Decrypt(String data, String key, String iv, SymmetricBuilder.WorkModel workModel, SymmetricBuilder.Padding padding) {
        byte[] encrypt = Base64.decodeBase64(data);
        byte[] decrypt = CryptoFactory.getCrypto(Algorithm.DES3)
                .decrypt(new SymmetricBuilder()
                        .data(encrypt)
                        .key(key)
                        .iv(iv)
                        .workModel(workModel)
                        .padding(padding)
                        );
        return new String(decrypt, DEFAULT_CHARSET);
    }

    public static String aesEncrypt(String data) {
        return aesEncrypt(data, null, null, null, null);
    }

    public static String aesDecrypt(String data) {
        return aesDecrypt(data, null, null, null, null);
    }

    public static String aesEncrypt(String data, String key) {
        return aesEncrypt(data, key, null, null, null);
    }

    public static String aesDecrypt(String data, String key) {
        return aesDecrypt(data, key, null, null, null);
    }

    public static String aesEncrypt(String data, String key, String iv, SymmetricBuilder.WorkModel workModel, SymmetricBuilder.Padding padding) {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.AES)
                .encrypt(new SymmetricBuilder()
                        .data(data.getBytes(DEFAULT_CHARSET))
                        .key(key)
                        .iv(iv)
                        .workModel(workModel)
                        .padding(padding)
                        );
        return Base64.encodeBase64URLSafeString(encryt);
    }

    public static String aesDecrypt(String data, String key, String iv, SymmetricBuilder.WorkModel workModel, SymmetricBuilder.Padding padding) {
        byte[] encrypt = Base64.decodeBase64(data);
        byte[] decrypt = CryptoFactory.getCrypto(Algorithm.AES)
                .decrypt(new SymmetricBuilder()
                        .data(encrypt)
                        .key(key)
                        .iv(iv)
                        .workModel(workModel)
                        .padding(padding)
                        );
        return new String(decrypt, DEFAULT_CHARSET);
    }

    public static String encryptByPBEWithMd5AndDes(String data, String key, String salt) {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndDes)
                .encrypt(new PBEBuilder()
                        .data(data.getBytes(DEFAULT_CHARSET))
                        .key(key)
                        .salt(salt)
                        );
        return Base64.encodeBase64URLSafeString(encryt);
    }

    public static String decryptByPBEWithMd5AndDes(String data, String key, String salt) {
        byte[] encrypt = Base64.decodeBase64(data);
        byte[] decrypt = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndDes)
                .decrypt(new PBEBuilder()
                        .data(encrypt)
                        .key(key)
                        .salt(salt)
                        );
        return new String(decrypt, DEFAULT_CHARSET);
    }

    public static String encryptByPBEWithMD5AndTripleDES(String data, String key, String salt) {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndTripleDES)
                .encrypt(new PBEBuilder()
                        .data(data.getBytes(DEFAULT_CHARSET))
                        .key(key)
                        .salt(salt)
                        );
        return Base64.encodeBase64URLSafeString(encryt);
    }

    public static String decryptByPBEWithMD5AndTripleDES(String data, String key, String salt) {
        byte[] encrypt = Base64.decodeBase64(data);
        byte[] decrypt = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndTripleDES)
                .decrypt(new PBEBuilder()
                        .data(encrypt)
                        .key(key)
                        .salt(salt)
                        );
        return new String(decrypt, DEFAULT_CHARSET);
    }

    public static String encryptByPBEWithSHA1AndRC2_40(String data, String key, String salt) {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.PBEWithSHA1AndRC2_40)
                .encrypt(new PBEBuilder()
                        .data(data.getBytes(DEFAULT_CHARSET))
                        .key(key)
                        .salt(salt)
                        );
        return Base64.encodeBase64URLSafeString(encryt);
    }

    public static String decryptByPBEWithSHA1AndRC2_40(String data, String key, String salt) {
        byte[] encrypt = Base64.decodeBase64(data);
        byte[] decrypt = CryptoFactory.getCrypto(Algorithm.PBEWithSHA1AndRC2_40)
                .decrypt(new PBEBuilder()
                        .data(encrypt)
                        .key(key)
                        .salt(salt)
                        );
        return new String(decrypt, DEFAULT_CHARSET);
    }


    //================= 非对称加密/解密 =================//

    public static String rsaPublicEncrypt(String data, String key) {
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        byte[] encry = rsa.encrypt(new AsymmetricBuilder().data(data.getBytes(DEFAULT_CHARSET)).publicKey(key));
        return Base64.encodeBase64URLSafeString(encry);
    }

    public static String rsaPrivateDecrypt(String data, String key) {
        byte[] encrypt = Base64.decodeBase64(data);
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        byte[] decrypt = rsa.decrypt(new AsymmetricBuilder().data(encrypt).privateKey(key));
        return new String(decrypt, DEFAULT_CHARSET);
    }


    public static String rsaPrivateEncrypt(String data, String key) {
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        byte[] encry = rsa.encrypt(new AsymmetricBuilder().data(data.getBytes(DEFAULT_CHARSET)).privateKey(key));
        return Base64.encodeBase64URLSafeString(encry);
    }

    public static String rsaPublicDecrypt(String data, String key) {
        byte[] encrypt = Base64.decodeBase64(data);
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        byte[] decrypt = rsa.decrypt(new AsymmetricBuilder().data(encrypt).publicKey(key));
        return new String(decrypt, DEFAULT_CHARSET);
    }
}
