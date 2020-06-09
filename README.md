# 通用加密解密封装

- Base64
- 摘要算法：MD5/SHA(1/256/384/512)
- 带密钥摘要算法：HmacMD5/HmacSHA1/HmacSHA256/HmacSHA384/HmacSHA512
- CRC32
- 对称加密：DES/DES3/AES
- 基于口令加密PBE：- PBEWithMd5AndDes/PBEWithMd5AndTripleDES/PBEWithSHA1AndDESede/PBEWithSHA1AndRC2_40
- 非对称加密：RSA
- PBKDF2WithHmacSHA512/PBKDF2WithHmacSHA256/PBKDF2WithHmacSHA1
- ARGON_2I/ARGON_2D/ARGON_2ID

# demo
```java
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
    
     @Test
    public void t2(){
        String data = "Pass123456";
        String hash = Argon2Helper.hash_2d(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2d(hash, data, 2));

        hash = Argon2Helper.hash_2i(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2i(hash, data, 2));

        hash = Argon2Helper.hash_2Id(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2Id(hash, data, 2));
    }
```
