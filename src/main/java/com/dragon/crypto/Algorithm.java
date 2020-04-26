package com.dragon.crypto;

/**
 * @ClassName: Algorithm
 * @Description: 支持的算法列表
 * @Author: pengl
 * @Date: 2020/3/27 20:58
 * @Version V1.0
 */
public enum Algorithm {
    Base64("Base64"),
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    HmacMD5("HmacMD5"),
    HmacSHA1("HmacSHA1"),
    HmacSHA256("HmacSHA256"),
    HmacSHA384("HmacSHA384"),
    HmacSHA512("HmacSHA512"),
    CRC32("CRC32"),
    DES("DES"),
    DES3("DESede"),
    AES("AES"),
    PBEWithMd5AndDes("PBEWithMD5AndDES"),
    PBEWithMd5AndTripleDES("PBEWithMD5AndTripleDES"),
    PBEWithSHA1AndDESede("PBEWithSHA1AndDESede"),
    PBEWithSHA1AndRC2_40("PBEWithSHA1AndRC2_40"),
    RSA("RSA");

    private String code;

    private Algorithm(String code) {
        this.code = code;
    }

    public String getCode() {
        return this.code;
    }

}
