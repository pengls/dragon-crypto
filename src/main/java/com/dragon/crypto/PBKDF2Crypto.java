package com.dragon.crypto;

import com.dragon.crypto.builder.BasicBuilder;
import com.dragon.crypto.builder.PBEBuilder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

/**
 * @ClassName: PBKDF2Crypto
 * @Description: PBKDF2Crypto
 * @Author: pengl
 * @Date: 2020/6/8 17:29
 * @Version V1.0
 */
public abstract class PBKDF2Crypto implements Crypto {
    private static final int CYCLE_TIMES = 20000;
    protected static final String DEFAULT_SALT_32 = "ks*&%$)1sd123sdxplkju+_)(23&^ysh";

    @Override
    public byte[] encrypt(BasicBuilder builder) {
        return pbkdf2(builder);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(new PBEBuilder().data(data));
    }


    private byte[] pbkdf2(BasicBuilder builder) {
        Assert.isInstanceOf(PBEBuilder.class, builder, "please use PBEBuilder build params.");
        PBEBuilder pbeBuilder = (PBEBuilder) builder;
        byte[] data = pbeBuilder.getData();
        Assert.notEmpty(data, "data is null or empty");
        String salt = Utils.isBlank(pbeBuilder.getSalt()) ? DEFAULT_SALT_32 : pbeBuilder.getSalt();
        try {
            KeySpec spec = new PBEKeySpec(getChars(data), salt.getBytes(StandardCharsets.UTF_8), CYCLE_TIMES, 256);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(current().getCode());
            byte[] hash = keyFactory.generateSecret(spec).getEncoded();
            return hash;
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private char[] getChars(byte[] bytes) {
        Charset cs = Charset.forName("UTF-8");
        ByteBuffer bb = ByteBuffer.allocate(bytes.length);
        bb.put(bytes).flip();
        CharBuffer cb = cs.decode(bb);
        return cb.array();
    }
}
