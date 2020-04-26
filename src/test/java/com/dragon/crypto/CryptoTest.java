package com.dragon.crypto;

import org.apache.commons.codec.binary.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @ClassName: CryptoTest
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/3/28 10:31
 * @Version V1.0
 */
public class CryptoTest extends Perform{
    String str = "!@#$%^&*()_+~（）abc 中文";
    String str2_8 = "qweroiuy12345678";
    private String key = "1asssdsdc212";

    void print(String str){
        System.out.println(str);
    }

    @Test
    public void base64Test() {
        byte[] encry = CryptoFactory.getCrypto(Algorithm.Base64).encrypt(str.getBytes());
        String encryString = StrUtils.newStringUtf8(encry);
        print("encry-->" + encryString);
        print("decry-->" + StrUtils.newStringUtf8(CryptoFactory.getCrypto(Algorithm.Base64).decrypt(encry)));

    }

   @Test
    public void md5Test() {
        byte[] encryt = CryptoFactory.getCrypto(Algorithm.MD5).encrypt(str.getBytes());
        System.out.println(Hex.encodeHexString(encryt));
    }

    @Test
    public void shaTest() {
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA1).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA256).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA384).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.SHA512).encrypt(str.getBytes())));
    }

   @Test
    public void hmacTest() {
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacMD5).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA1).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA256).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA384).encrypt(str.getBytes())));
        System.out.println(Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA512).encrypt(str.getBytes())));
    }

    @Test
    public void aesTest() {
        String key = "1234567890-=plmkoijnbhuygvcftrdx";
        String iv = "0okmnji98uyhgbvf";
        Crypto aes = CryptoFactory.getCrypto(Algorithm.AES);
        //采用默认key， iv， 工作模式 ，填充方式
        String defEncry = new String(aes.encrypt(CryptoParam.builder().data(str.getBytes()).build()));
        System.out.println("默认KEY,IV,工作模式,填充方式加密：" + defEncry);
        System.out.println("默认KEY,IV,工作模式,填充方式解密：" + aes.decrypt(defEncry.getBytes()));
    }
    /*
    *//*@Test
    public void des3Test(){
        String encrypt = CryptoFactory.getCrypto(Algorithm.DES3_ECB).encrypt(str);
        System.out.println(encrypt);
        encrypt = CryptoFactory.getCrypto(Algorithm.DES3_ECB).encrypt(str);
        System.out.println(encrypt);
        System.out.println(CryptoFactory.getCrypto(Algorithm.DES3_ECB).decrypt(encrypt));
        System.out.println(CryptoFactory.getCrypto(Algorithm.DES3_ECB).decrypt(encrypt));
    }

    @Test
    public void des3Test2(){
        String encrypt = CryptoFactory.getCrypto(Algorithm.DES3_CBC).encrypt(str);
        System.out.println(encrypt);
        System.out.println(CryptoFactory.getCrypto(Algorithm.DES3_CBC).decrypt(encrypt));
    }

    @Test
    public void aesTest(){
        String encrypt = CryptoFactory.getCrypto(Algorithm.AES_ECB).encrypt(str);
        System.out.println(encrypt);
        System.out.println(CryptoFactory.getCrypto(Algorithm.AES_ECB).decrypt(encrypt));
    }

    @Test
    public void aesTest2(){
        String encrypt = CryptoFactory.getCrypto(Algorithm.AES_CBC).encrypt(str);
        System.out.println(encrypt);
        System.out.println(CryptoFactory.getCrypto(Algorithm.AES_CBC).decrypt(encrypt));
    }*//*

    @Test
    public void pbeTest() {
        Crypto pbe = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndDes);
        String encrypt = pbe.encryptString(str);
        System.out.println(encrypt);
        System.out.println(pbe.decryptString(encrypt));

        encrypt = pbe.encryptString(CryptoParam.builder().data(str).key(key).salt("12345678").build());
        System.out.println(encrypt);
        System.out.println(pbe.decryptString(CryptoParam.builder().data(encrypt).key(key).salt("12345678").build()));

    }*/

    @Test
    public void rsaTest() {
        KeyPairs keyPairs = RSACoder.keyPairs();
        System.out.println("===========生成密钥对===========\n->PublickKey \n" + keyPairs.getPublicKey() + "\n->PrivateKey \n" + keyPairs.getPrivateKey());
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        //公钥加密，私钥解密
        byte[] encry = rsa.encrypt(CryptoParam.builder().data(str.getBytes()).publicKey(keyPairs.getPublicKey()).build());
        System.out.println("公钥加密：" + Hex.encodeHexString(encry));

        byte[] decry = rsa.decrypt(CryptoParam.builder().data(encry).privateKey(keyPairs.getPrivateKey()).build());
        System.out.println("私钥解密：" + new String(decry));


    }
}
