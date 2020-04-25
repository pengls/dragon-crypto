package com.dragon.crypto;

/**
 * @ClassName: CryptoParam
 * @Description: encry/decry params builder
 * @Author: pengl
 * @Date: 2020/3/28 21:16
 * @Version V1.0
 */
public class CryptoParam {
    private byte[] data;
    private String key;
    private String iv;

    /**
     * AES/DES3 --> CBC/ECB...
     */
    private WorkModel workModel;
    /**
     * AES/DES3 --> padding:PKCS5padding...
     */
    private Padding padding;
    /**
     * RSA
     */
    private String publicKey;
    private String privateKey;

    /**
     * PBE
     */
    private String salt;

    public String getKey() {
        return key;
    }

    public String getIv() {
        return iv;
    }

    public WorkModel getWorkModel() {
        return workModel == null ? SymmetricCrypto.DEFAULT_WORK_MODEL : workModel;
    }

    public Padding getPadding() {
        return padding == null ? SymmetricCrypto.DEFAULT_PADDING : padding;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public void setWorkModel(WorkModel workModel) {
        this.workModel = workModel;
    }

    public void setPadding(Padding padding) {
        this.padding = padding;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    //================= Builder pattern =================//

    public static CryptoParamBuilder builder() {
        return new CryptoParamBuilder();
    }

    private CryptoParam(byte[] data, String key, String iv, WorkModel workModel, Padding padding, String publicKey, String privateKey, String salt) {
        this.data = data;
        this.key = key;
        this.iv = iv;
        this.workModel = workModel;
        this.padding = padding;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.salt = salt;
    }

    public static class CryptoParamBuilder {
        private byte[] data;
        private String key;
        private String iv;
        private WorkModel workModel;
        private Padding padding;
        private String publicKey;
        private String privateKey;
        private String salt;

        public CryptoParamBuilder data(byte[] data) {
            this.data = data;
            return this;
        }

        public CryptoParamBuilder key(String key) {
            this.key = key;
            return this;
        }

        public CryptoParamBuilder iv(String iv) {
            this.iv = iv;
            return this;
        }

        public CryptoParamBuilder workModel(WorkModel workModel) {
            this.workModel = workModel;
            return this;
        }

        public CryptoParamBuilder padding(Padding padding) {
            this.padding = padding;
            return this;
        }

        public CryptoParamBuilder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public CryptoParamBuilder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public CryptoParamBuilder salt(String salt) {
            this.salt = salt;
            return this;
        }

        public CryptoParam build() {
            return new CryptoParam(data, key, iv, workModel, padding, publicKey, privateKey, salt);
        }
    }

    /**
     * @ClassName: CryptoParam
     * @Description: All must iv, But ECB
     * @Author: pengl
     * @Date: 2020/3/29 12:12
     * @Version V1.0
     */
    public enum WorkModel {
        ECB,
        CBC,
        PCBC,
        CTR,
        CTS,
        CFB,
        CFB128,
        OFB,
        OFB128
    }

    public enum Padding {
        /**
         * this padding model, The original must be a multiple of 8
         */
        NoPadding,
        /**
         * Every encrypted ciphertext is the same
         */
        PKCS5Padding,
        /**
         * Every encrypted ciphertext 50% is the same
         */
        ISO10126Padding
    }
}
