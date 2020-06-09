package com.dragon.crypto;

import com.dragon.crypto.builder.AsymmetricBuilder;
import com.dragon.crypto.builder.PBEBuilder;
import com.dragon.crypto.builder.SymmetricBuilder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * @ClassName: CryptoTest
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/3/28 10:31
 * @Version V1.0
 */
public class CryptoTest extends Perform {
    String str = "!@#$%^&*()_+~（）abc 中文";
    String str2_8 = "qweroiuy12345678";
    private String key = "1asssdsdc212";

    void print(String str) {
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
        String key = "jskd231*&%";
        String iv = "29238^%%$ss";
        String str = "2010202010";
        Crypto aes = CryptoFactory.getCrypto(Algorithm.AES);
        //采用默认key， iv， 工作模式 ，填充方式
        String miwen = Base64.encodeBase64String(aes.encrypt(new SymmetricBuilder().data(str.getBytes())));
        System.out.println("默认KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("默认KEY,IV,工作模式,填充方式解密：" + new String(aes.decrypt(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));

        //采用自定义key，iv，工作模式，填充方式
        miwen = Base64.encodeBase64String(aes.encrypt(new SymmetricBuilder().data(str.getBytes()).key(key).iv(iv).workModel(SymmetricBuilder.WorkModel.GCM).padding(SymmetricBuilder.Padding.PKCS5Padding)));
        System.out.println("指定KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("指定KEY,IV,工作模式,填充方式解密：" + new String(aes.decrypt(new SymmetricBuilder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                .iv(iv).workModel(SymmetricBuilder.WorkModel.GCM).padding(SymmetricBuilder.Padding.PKCS5Padding)), StandardCharsets.UTF_8));
    }

    @Test
    public void desTest() {
        String key = "(3)_&*uiku@..!123";
        String iv = "K*&^%09P..iqx";
        Crypto des = CryptoFactory.getCrypto(Algorithm.DES);
        //采用默认key， iv， 工作模式 ，填充方式
        String miwen = Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes())));
        System.out.println("默认KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("默认KEY,IV,工作模式,填充方式解密：" + new String(des.decrypt(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));

        //采用自定义key，iv，工作模式，填充方式
        miwen = Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes()).key(key).iv(iv).workModel(SymmetricBuilder.WorkModel.OFB).padding(SymmetricBuilder.Padding.PKCS5Padding)));
        System.out.println("指定KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("指定KEY,IV,工作模式,填充方式解密：" + new String(des.decrypt(new SymmetricBuilder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                .iv(iv).workModel(SymmetricBuilder.WorkModel.OFB).padding(SymmetricBuilder.Padding.PKCS5Padding)), StandardCharsets.UTF_8));
    }
    @Test
    public void des3Test() {
        String key = "(3)_&*uiku@..!123";
        String iv = "K*&^%09P..iqx";
        Crypto des = CryptoFactory.getCrypto(Algorithm.DES3);
        //采用默认key， iv， 工作模式 ，填充方式
        String miwen = Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes())));
        System.out.println("默认KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("默认KEY,IV,工作模式,填充方式解密：" + new String(des.decrypt(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));

        //采用自定义key，iv，工作模式，填充方式
        miwen = Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes()).key(key).iv(iv).workModel(SymmetricBuilder.WorkModel.OFB).padding(SymmetricBuilder.Padding.PKCS5Padding)));
        System.out.println("指定KEY,IV,工作模式,填充方式加密：" + miwen + "--" + miwen.length());
        System.out.println("指定KEY,IV,工作模式,填充方式解密：" + new String(des.decrypt(new SymmetricBuilder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                .iv(iv).workModel(SymmetricBuilder.WorkModel.OFB).padding(SymmetricBuilder.Padding.PKCS5Padding)), StandardCharsets.UTF_8));
    }

    @Test
    public void pbeTest() {
        Crypto pbe = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndDes);
        String miwen = Base64.encodeBase64String(pbe.encrypt(new PBEBuilder().data(str.getBytes()).key("sdsddssd").salt("sdsdsds2")));
        System.out.println(miwen);
        System.out.println("默认KEY,IV,工作模式,填充方式解密：" + new String(pbe.decrypt(new PBEBuilder().key("sdsddssd").salt("sdsdsds2").data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8)))), StandardCharsets.UTF_8));
    }
    /*
     *
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

        encrypt = pbe.encryptString(CryptoParam.builder().data(str).key(key).salt("12345678"));
        System.out.println(encrypt);
        System.out.println(pbe.decryptString(CryptoParam.builder().data(encrypt).key(key).salt("12345678")));

    }*/

    @Test
    public void rsaTest() {
        KeyPairs keyPairs = RSACoder.keyPairs();
        System.out.println("===========生成密钥对===========\n->PublickKey \n" + keyPairs.getPublicKey() + "\n->PrivateKey \n" + keyPairs.getPrivateKey());
        Crypto rsa = CryptoFactory.getCrypto(Algorithm.RSA);
        //公钥加密，私钥解密
        byte[] encry = rsa.encrypt(new AsymmetricBuilder().data(str.getBytes()).publicKey(keyPairs.getPublicKey()));
        System.out.println("公钥加密：" + Hex.encodeHexString(encry));

        byte[] decry = rsa.decrypt(new AsymmetricBuilder().data(encry).privateKey(keyPairs.getPrivateKey()));
        System.out.println("私钥解密：" + new String(decry));


    }
}
