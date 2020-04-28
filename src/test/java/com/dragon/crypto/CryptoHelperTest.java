package com.dragon.crypto;

import org.junit.Test;

/**
 * @ClassName: CryptoHelperTest
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/4/26 22:29
 * @Version V1.0
 */
public class CryptoHelperTest extends Perform{
    private String ming = "!@#$%^&*()_+~（）abc 中文";
    private String hmac_key = "abcd";
    private String des_key = "*&123sxg1qwsdfrtgyh654bn";
    private String des_iv = "ijs)*&^%";
    private String aes_key = "*&123sxg1qwsdfrtgyh654bn-=po2wsq";
    private String aes_iv = "ijs)*&^%ijs)*&^%";
    private String pbe_key = "KEYT(*&qwsksjdhfnbejslqwosdjqaxc";
    private String pbe_salt = "SALT(*&!";

    /**
     * 摘要算法测试
     */
    @Test
    public void t1(){
        System.out.println(CryptoHelper.md5(ming));
        System.out.println(CryptoHelper.sha256(ming));
        System.out.println(CryptoHelper.hmacMD5(ming, hmac_key));
        System.out.println(CryptoHelper.hmacSHA256(ming, hmac_key));
    }

    /**
     * 3重DES加密解密
     */
    @Test
    public void t2(){
        String miwen = CryptoHelper.des3Encrypt(ming);
        System.out.println(miwen);
        System.out.println(CryptoHelper.des3Decrypt(miwen));

        miwen = CryptoHelper.des3Encrypt(ming, des_key);
        System.out.println(miwen);
        System.out.println(CryptoHelper.des3Decrypt(miwen, des_key));

        miwen = CryptoHelper.des3Encrypt(ming, des_key, des_iv, CryptoParam.WorkModel.PCBC, CryptoParam.Padding.ISO10126Padding);
        System.out.println(miwen);
        System.out.println(CryptoHelper.des3Decrypt(miwen, des_key, des_iv, CryptoParam.WorkModel.PCBC, CryptoParam.Padding.ISO10126Padding));
    }

    /**
     * AES加密解密
     */
    @Test
    public void t3(){
        String miwen = CryptoHelper.aesEncrypt(ming);
        System.out.println(miwen);
        System.out.println(CryptoHelper.aesDecrypt(miwen));

        miwen = CryptoHelper.aesEncrypt(ming, aes_key);
        System.out.println(miwen);
        System.out.println(CryptoHelper.aesDecrypt(miwen, aes_key));

        miwen = CryptoHelper.aesEncrypt(ming, aes_key, aes_iv, CryptoParam.WorkModel.PCBC, CryptoParam.Padding.ISO10126Padding);
        System.out.println(miwen);
        System.out.println(CryptoHelper.aesDecrypt(miwen, aes_key, aes_iv, CryptoParam.WorkModel.PCBC, CryptoParam.Padding.ISO10126Padding));
    }

    /**
     * PBE
     */
    @Test
    public void t4(){
        String miwen = CryptoHelper.encryptByPBEWithMd5AndDes(ming, pbe_key, pbe_salt);
        System.out.println(miwen);
        System.out.println(CryptoHelper.decryptByPBEWithMd5AndDes(miwen, pbe_key, pbe_salt));

        miwen = CryptoHelper.encryptByPBEWithMD5AndTripleDES(ming, pbe_key, pbe_salt);
        System.out.println(miwen);
        System.out.println(CryptoHelper.decryptByPBEWithMD5AndTripleDES(miwen, pbe_key, pbe_salt));

        miwen = CryptoHelper.encryptByPBEWithSHA1AndRC2_40(ming, pbe_key, pbe_salt);
        System.out.println(miwen);
        System.out.println(CryptoHelper.decryptByPBEWithSHA1AndRC2_40(miwen, pbe_key, pbe_salt));
    }

    /**
     * RSA
     */
    @Test
    public void t5(){
        KeyPairs keyPairs = RSACoder.keyPairs();
        System.out.println("===========生成密钥对===========\n->PublickKey \n" + keyPairs.getPublicKey() + "\n->PrivateKey \n" + keyPairs.getPrivateKey());

        String miwen = CryptoHelper.rsaPublicEncrypt(ming, keyPairs.getPublicKey());
        System.out.println(miwen);
        System.out.println(CryptoHelper.rsaPrivateDecrypt(miwen, keyPairs.getPrivateKey()));

        miwen = CryptoHelper.rsaPrivateEncrypt(ming, keyPairs.getPrivateKey());
        System.out.println(miwen);
        System.out.println(CryptoHelper.rsaPublicDecrypt(miwen, keyPairs.getPublicKey()));
    }
}
