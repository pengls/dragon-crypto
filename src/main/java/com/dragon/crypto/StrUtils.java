package com.dragon.crypto;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @ClassName: StrUtils
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/4/2 22:37
 * @Version V1.0
 */
public class StrUtils {

    /**
     * byte[] --> string
     * @param bytes
     * @param charset
     * @return
     */
    public static String newString(byte[] bytes, Charset charset) {
        return bytes == null ? null : new String(bytes, charset);
    }

    public static String newString(byte[] bytes, String charsetName) {
        if (bytes == null) {
            return null;
        } else {
            try {
                return new String(bytes, charsetName);
            } catch (UnsupportedEncodingException var3) {
                throw new IllegalStateException(charsetName, var3);
            }
        }
    }

    public static String newStringIso8859_1(byte[] bytes) {
        return newString(bytes, StandardCharsets.ISO_8859_1);
    }

    public static String newStringUsAscii(byte[] bytes) {
        return newString(bytes, StandardCharsets.US_ASCII);
    }

    public static String newStringUtf16(byte[] bytes) {
        return newString(bytes, StandardCharsets.UTF_16);
    }

    public static String newStringUtf16Be(byte[] bytes) {
        return newString(bytes, StandardCharsets.UTF_16BE);
    }

    public static String newStringUtf16Le(byte[] bytes) {
        return newString(bytes, StandardCharsets.UTF_16LE);
    }

    public static String newStringUtf8(byte[] bytes) {
        return newString(bytes, StandardCharsets.UTF_8);
    }
}
