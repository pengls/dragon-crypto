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
public class ThreadTest {
    static ExecutorService threadPool = new ThreadPoolExecutor(2, 5,
            0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>());
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
            threadPool.execute(() -> {
                //while (true) {
                    if (encryptType == 1) {
                        encryptAndDecryptByAES(loop);
                    } else {
                        encryptAndDecryptByDES(loop);
                    }
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                //}
            });
        }

    }

    private static void encryptAndDecryptByAES(int loop) {
        for (int i = 0; i < loop; i++) {
            String miwen = Base64.encodeBase64String(aes.encrypt(CryptoParam.builder().data(str.getBytes()).key(key).iv(iv).workModel(CryptoParam.WorkModel.GCM).padding(CryptoParam.Padding.NoPadding).build()));
            String mingwen = new String(aes.decrypt(CryptoParam.builder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                    .iv(iv).workModel(CryptoParam.WorkModel.GCM).padding(CryptoParam.Padding.NoPadding).build()), StandardCharsets.UTF_8);
            System.out.println(String.format("%s,%s,%s", Thread.currentThread().getName(), miwen, mingwen));
        }
    }

    private static void encryptAndDecryptByDES(int loop) {
        for (int i = 0; i < loop; i++) {
            String miwen = Base64.encodeBase64String(des.encrypt(CryptoParam.builder().data(str.getBytes()).key(key).iv(iv).workModel(CryptoParam.WorkModel.CBC).padding(CryptoParam.Padding.PKCS5Padding).build()));
            String mingwen = new String(des.decrypt(CryptoParam.builder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                    .iv(iv).workModel(CryptoParam.WorkModel.CBC).padding(CryptoParam.Padding.PKCS5Padding).build()), StandardCharsets.UTF_8);
            System.out.println(String.format("%s,%s,%s", Thread.currentThread().getName(), miwen, mingwen));
        }
    }
}
