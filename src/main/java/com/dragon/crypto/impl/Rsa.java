package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.AsymmetricCrypto;

/**
 * @ClassName: Rsa
 * @Description: RAS
 * @Author: pengl
 * @Date: 2020/3/29 15:53
 * @Version V1.0
 */
public class Rsa extends AsymmetricCrypto {
    @Override
    public Algorithm current() {
        return Algorithm.RSA;
    }
}
