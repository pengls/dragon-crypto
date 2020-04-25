package com.dragon.crypto;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @ClassName: RSACoder
 * @Description: RSACoder
 * @Author: pengl
 * @Date: 2020/3/28 20:16
 * @Version V1.0
 */
public abstract class RSACoder {
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 1024;


    /**
     * @MethodName: keyPairs
     * @Description: get keyPairs
     * @Author: pengl
     * @Date: 2020/3/28 20:51
     * @Version V1.0
     */
    public static KeyPairs keyPairs() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            String publicKeyStr = Base64.encodeBase64URLSafeString(publicKey.getEncoded());
            String privateKeyStr = Base64.encodeBase64URLSafeString(privateKey.getEncoded());
            return new KeyPairs(publicKeyStr, privateKeyStr);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    public static void main(String[] args) {
        KeyPairs keyPairs = keyPairs();
        System.out.println(keyPairs.getPublicKey());
        System.out.println(keyPairs.getPrivateKey());
    }
}
