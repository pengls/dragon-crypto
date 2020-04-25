package com.dragon.crypto;

/**
 * @ClassName: CryptoException
 * @Description: crypto Exception
 * @Author: pengl
 * @Date: 2020/3/27 21:07
 * @Version V1.0
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String errorMsg) {
        super(errorMsg);
    }

    public CryptoException(String errorMsg, Throwable tr) {
        super(errorMsg, tr);
    }
}
