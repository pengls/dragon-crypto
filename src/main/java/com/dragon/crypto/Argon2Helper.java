package com.dragon.crypto;

import com.dragon.crypto.builder.Argon2Builder;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @ClassName: Argon2Helper
 * @Description: Argon2Helper
 * @Author: pengl
 * @Date: 2020/6/9 12:54
 * @Version V1.0
 */
public final class Argon2Helper {
    private static final int DEFAULT_SALT_LENGTH = 16;
    private static final int DEFAULT_HASH_LENGTH = 32;
    private static final int DEFAULT_ITERATIONS = 10;
    private static final int DEFAULT_MEMORY = 65536;
    private static final int DEFAULT_PARALLELISM = 1;
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private static final Argon2 ARGON_2I = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    private static final Argon2 ARGON_2D = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    private static final Argon2 ARGON_2ID = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);

    private static void setDefault(Argon2Builder builder) {
        if (Utils.isAllBlank(builder.getData(), builder.getPass())) {
            throw new CryptoException("pass or data must not empty");
        }

        if (builder.getHashLength() == 0) {
            builder.setHashLength(DEFAULT_HASH_LENGTH);
        }
        if (builder.getIterations() == 0) {
            builder.setIterations(DEFAULT_ITERATIONS);
        }
        if (builder.getMemory() == 0) {
            builder.setMemory(DEFAULT_MEMORY);
        }
        if (builder.getParallelism() == 0) {
            builder.setParallelism(DEFAULT_PARALLELISM);
        }
        if (builder.getSaltLength() == 0) {
            builder.setSaltLength(DEFAULT_SALT_LENGTH);
        }
    }

    private static void wipeArray(Argon2 argon2, Argon2Builder builder) {
        if (Utils.isNotBlank(builder.getPass())) {
            argon2.wipeArray(builder.getPass().toCharArray());
        } else if (Utils.isNotBlank(builder.getData())) {
            argon2.wipeArray(builder.getData().getBytes(DEFAULT_CHARSET));
        }
    }

    public static String hash_2i(Argon2Builder builder) {
        setDefault(builder);
        try {
            return Utils.isNotBlank(builder.getPass()) ?
                    ARGON_2I.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getPass().toCharArray(), DEFAULT_CHARSET)
                    :
                    ARGON_2I.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getData().getBytes(DEFAULT_CHARSET));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        } finally {
            wipeArray(ARGON_2I, builder);
        }
    }

    /**
     * type , 1: pass   2:data
     *
     * @param str
     * @param type
     * @return
     */
    public static String hash_2i(String str, int type) {
        return type == 1 ? hash_2i(new Argon2Builder().pass(str)) : hash_2i(new Argon2Builder().data(str));
    }

    public static boolean verify_2i(String hash, String str, int type) {
        return type == 1 ? ARGON_2I.verify(hash, str.toCharArray(), DEFAULT_CHARSET) : ARGON_2I.verify(hash, str.getBytes(DEFAULT_CHARSET));

    }

    public static String hash_2d(Argon2Builder builder) {
        setDefault(builder);
        try {
            return Utils.isNotBlank(builder.getPass()) ?
                    ARGON_2D.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getPass().toCharArray(), DEFAULT_CHARSET)
                    :
                    ARGON_2D.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getData().getBytes(DEFAULT_CHARSET));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        } finally {
            wipeArray(ARGON_2D, builder);
        }
    }

    /**
     * type , 1: pass   2:data
     *
     * @param str
     * @param type
     * @return
     */
    public static String hash_2d(String str, int type) {
        return type == 1 ? hash_2d(new Argon2Builder().pass(str)) : hash_2d(new Argon2Builder().data(str));
    }

    public static boolean verify_2d(String hash, String str, int type) {
        return type == 1 ? ARGON_2D.verify(hash, str.toCharArray(), DEFAULT_CHARSET) : ARGON_2D.verify(hash, str.getBytes(DEFAULT_CHARSET));
    }

    public static String hash_2Id(Argon2Builder builder) {
        setDefault(builder);
        try {
            return Utils.isNotBlank(builder.getPass()) ?
                    ARGON_2ID.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getPass().toCharArray(), DEFAULT_CHARSET)
                    :
                    ARGON_2ID.hash(builder.getIterations(), builder.getMemory(), builder.getParallelism(), builder.getData().getBytes(DEFAULT_CHARSET));
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        } finally {
            wipeArray(ARGON_2ID, builder);
        }
    }

    /**
     * type , 1: pass   2:data
     *
     * @param str
     * @param type
     * @return
     */
    public static String hash_2Id(String str, int type) {
        return type == 1 ? hash_2Id(new Argon2Builder().pass(str)) : hash_2Id(new Argon2Builder().data(str));
    }

    public static boolean verify_2Id(String hash, String str, int type) {
        return type == 1 ? ARGON_2ID.verify(hash, str.toCharArray(), DEFAULT_CHARSET) : ARGON_2ID.verify(hash, str.getBytes(DEFAULT_CHARSET));
    }
}
