package com.dragon.crypto;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * @ClassName: ThreadTest
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/6/3 14:36
 * @Version V1.0
 */
public class ThreadTest2 {
    static String key = "jskd231*&%";
    static String iv = "29238^%%$ss";
    static String str = "2010202010";
    static Crypto aes = CryptoFactory.getCrypto(Algorithm.AES);
    static Crypto des = CryptoFactory.getCrypto(Algorithm.DES);

    public static void main(String[] args) throws InterruptedException {
        final int loop = (args == null || args.length == 0) ? 10 : Integer.parseInt(args[0]);
        final int threads = (args == null || args.length < 2) ? 5 : Integer.parseInt(args[1]);
        final int encryptType = (args == null || args.length < 3) ? 1 : Integer.parseInt(args[2]);

        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                if (encryptType == 1) {
                    encryptAndDecryptByAES(loop);
                } else {
                    encryptAndDecryptByDES(loop);
                }
            });
            t.start();
            t.join();
        }

    }

    private static void encryptAndDecryptByAES(int loop) {

    }

    private static void encryptAndDecryptByDES(int loop) {

    }
}
