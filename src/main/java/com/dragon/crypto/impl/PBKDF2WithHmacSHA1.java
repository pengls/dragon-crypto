package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.PBKDF2Crypto;

/**
 * @ClassName: PBKDF2WithHmacSHA1
 * @Description: PBKDF2WithHmacSHA1
 * @Author: pengl
 * @Date: 2020/6/8 17:32
 * @Version V1.0
 */
public class PBKDF2WithHmacSHA1 extends PBKDF2Crypto {
    @Override
    public Algorithm current() {
        return Algorithm.PBKDF2WithHmacSHA1;
    }
}
