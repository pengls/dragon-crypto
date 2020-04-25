package com.dragon.crypto;

import java.util.function.Supplier;

/**
 * @ClassName: Assert
 * @Description: Assert
 * @Author: pengl
 * @Date: 2020/3/31 20:14
 * @Version V1.0
 */
public final class Assert {

    public static void isNull(Object object, String message) {
        if (object != null) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void isNull(Object object, Supplier<String> messageSupplier) {
        if (object != null) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    public static void notNull(Object object, String message) {
        if (object == null) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void notNull(Object object, Supplier<String> messageSupplier) {
        if (object == null) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    public static void notBlank(String str, String message) {
        if (Utils.isBlank(str)) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void notBlank(String str, Supplier<String> messageSupplier) {
        if (null == str) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }
    public static void isAssignable(Class<?> superType, Class<?> subType, String message) {
        notNull(superType, "Super type to check against must not be null");
        if (subType == null || !superType.isAssignableFrom(subType)) {
            throw new IllegalArgumentException(message);
        }

    }

    public static void isAssignable(Class<?> superType, Class<?> subType, Supplier<String> messageSupplier) {
        notNull(superType, "Super type to check against must not be null");
        if (subType == null || !superType.isAssignableFrom(subType)) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    public static void isInstanceOf(Class<?> type, Object obj, String message) {
        notNull(type, "Type to check against must not be null");
        if (!type.isInstance(obj)) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void isInstanceOf(Class<?> type, Object obj, Supplier<String> messageSupplier) {
        notNull(type, "Type to check against must not be null");
        if (!type.isInstance(obj)) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    public static void notEmpty(byte[] bytes, Supplier<String> messageSupplier) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    public static void notEmpty(byte[] bytes, String message) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException(message);
        }
    }


    public static void isRangeIndex(int index, int size, String message) {
        if (index < 0 || index >= size) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void isRangeIndex(int index, int size, Supplier<String> messageSupplier) {
        if (index < 0 || index >= size) {
            throw new IllegalArgumentException(nullSafeGet(messageSupplier));
        }
    }

    private static String nullSafeGet(Supplier<String> messageSupplier) {
        return messageSupplier != null ? messageSupplier.get() : null;
    }
}
