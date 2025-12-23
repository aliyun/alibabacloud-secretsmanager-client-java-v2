package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class ByteBufferUtils {

    private ByteBufferUtils() {
        // do nothing
    }


    /**
     * 将字符串转换为字节缓冲区
     *
     * @param content 字符串内容
     * @return 字节缓冲区
     */
    public static ByteBuffer convertStringToByte(final String content) {
        return ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8));
    }
}
