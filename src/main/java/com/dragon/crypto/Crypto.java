package com.dragon.crypto;

import com.dragon.crypto.builder.BasicBuilder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @ClassName: Crypto
 * @Description: crypto interface
 * @Author: pengl
 * @Date: 2020/3/27 20:58
 * @Version V1.0
 */
public interface Crypto {
    /**
     * default key
     */
    String DEFAULT_KEY = "asdi!@#$%^&*~()_+AYHB";
    Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * @MethodName: encryptBytes
     * @Description: return a byte[]
     * @Author: pengl
     * @Date: 2020/4/1 22:24
     * @Version V1.0
     */
    byte[] encrypt(BasicBuilder builder);

    byte[] encrypt(byte[] bytes);

    /**
     * @MethodName: decryptBytes
     * @Description: return a byte[]
     * @Author: pengl
     * @Date: 2020/3/28 23:16
     * @Version V1.0
     */
    default byte[] decrypt(BasicBuilder builder) {
        throw new CryptoException("Unsupported Method !");
    }

    default byte[] decrypt(byte[] bytes) {
        throw new CryptoException("Unsupported Method !");
    }


    /**
     * @MethodName: current
     * @Description: return current algorithm
     * @Author: pengl
     * @Date: 2020/3/27 21:04
     * @Version V1.0
     */
    Algorithm current();

    /**
     * default SecretKey
     *
     * @param key
     * @return
     */
    default SecretKey toKey(final String key) {
        return new SecretKeySpec(key.getBytes(), current().getCode());
    }

    default SecretKey toKey(final byte[] key) {
        return new SecretKeySpec(key, current().getCode());
    }

    default void warn() {
    }

}
