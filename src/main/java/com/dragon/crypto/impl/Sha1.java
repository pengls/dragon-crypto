package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.DigestCrypto;

/**
 * @ClassName: Sha256
 * @Description: Sha256 encrypt
 * @Author: pengl
 * @Date: 2020/3/27 21:22
 * @Version V1.0
 */
public class Sha1 extends DigestCrypto {
    @Override
    public Algorithm current() {
        return Algorithm.SHA1;
    }
}
