package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class SignUtils {

    public static final String HEADER_DATE = "Date";
    public static final String HEADER_API_VERSION = "x-kms-apiversion";
    public static final String HEADER_API_NAME = "x-kms-apiname";
    public static final String HEADER_SIGNATURE_METHOD = "x-kms-signaturemethod";
    public static final String HEADER_ACCESS_KEY_ID = "x-kms-acccesskeyid";
    public static final String ALGO_RSA_PKCS1_SHA256 = "RSA_PKCS1_SHA_256";
    public static final String ACTION_GET_SECRET_VALUE = "GetSecretValue";
    public static final String API_VERSION_20160102 = "2016-01-02";

    /**
     * 从请求对象提取签名参数
     *
     * @param param 请求对象
     * @return query参数Map
     */
    public static Map<String, String> extractSignParams(Object param) {
        Map<String, Object> rawMap;
        if (param instanceof com.aliyun.tea.TeaModel) {
            rawMap = ((com.aliyun.tea.TeaModel) param).toMap();
        } else {
            Gson gson = new Gson();
            String json = gson.toJson(param);
            rawMap = gson.fromJson(json, new TypeToken<Map<String, Object>>() {
            }.getType());
        }
        Map<String, String> result = new HashMap<>();
        if (rawMap != null) {
            for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
                if (entry.getValue() != null && !entry.getValue().toString().isEmpty()) {
                    result.put(entry.getKey(), String.valueOf(entry.getValue()));
                }
            }
        }
        return result;
    }

    /**
     * 构建签名header
     *
     * @param tokenId tokenKeyId
     * @param action  API action名称
     * @return header Map
     */
    public static Map<String, String> buildSignHeaders(String tokenId, String action) {
        Map<String, String> header = new HashMap<>();
        header.put(HEADER_ACCESS_KEY_ID, tokenId);
        header.put(HEADER_SIGNATURE_METHOD, ALGO_RSA_PKCS1_SHA256);
        header.put(HEADER_DATE, ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        header.put(HEADER_API_NAME, action);
        header.put(HEADER_API_VERSION, API_VERSION_20160102);
        return header;
    }

    /**
     * 对请求参数和header进行RSA签名
     *
     * @param queryParams query参数
     * @param header      header参数
     * @param privateKey  私钥PEM
     * @return Base64编码的签名
     * @throws Exception 签名异常
     */
    public static String sign(Map<String, String> queryParams, Map<String, String> header, String privateKey) throws Exception {
        Map<String, String> args = new HashMap<>();
        if (queryParams != null) {
            args.putAll(queryParams);
        }
        if (header != null) {
            args.putAll(header);
        }
        String toSignString = buildStringToSign(args);
        return sha256WithRsa(toSignString, privateKey);
    }

    private static String buildStringToSign(Map<String, String> args) {
        List<String> keys = new ArrayList<>(args.keySet());
        Collections.sort(keys);
        StringBuilder buf = new StringBuilder();
        for (String key : keys) {
            String value = args.get(key);
            if (buf.length() > 0) {
                buf.append('&');
            }
            buf.append(percentEncode(key)).append('=').append(percentEncode(value));
        }
        return buf.toString();
    }

    private static String percentEncode(String s) {
        if (s == null) {
            return "";
        }
        String encoded;
        try {
            encoded = URLEncoder.encode(s, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
    }

    private static String sha256WithRsa(String source, String secret) throws Exception {
        String privateKeyPEM = secret
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PrivateKey privateKey;

        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            // PKCS1 -> PKCS8
            byte[] pkcs8Bytes = wrapPkcs1ToPkcs8(encoded);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        }

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(source.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1Bytes) {

        int pkcs1Len = pkcs1Bytes.length;
        int totalLen = pkcs1Len + 22 + 4; // 22 = header length, 4 = 2 length fields

        byte[] pkcs8Bytes = new byte[totalLen];
        int offset = 0;

        // SEQUENCE
        pkcs8Bytes[offset++] = 0x30;
        pkcs8Bytes[offset++] = (byte) 0x82;
        pkcs8Bytes[offset++] = (byte) ((totalLen - 4) >> 8);
        pkcs8Bytes[offset++] = (byte) (totalLen - 4);

        // version INTEGER 0
        pkcs8Bytes[offset++] = 0x02;
        pkcs8Bytes[offset++] = 0x01;
        pkcs8Bytes[offset++] = 0x00;

        // AlgorithmIdentifier for RSA
        pkcs8Bytes[offset++] = 0x30;
        pkcs8Bytes[offset++] = 0x0D;
        pkcs8Bytes[offset++] = 0x06;
        pkcs8Bytes[offset++] = 0x09;
        pkcs8Bytes[offset++] = 0x2A;
        pkcs8Bytes[offset++] = (byte) 0x86;
        pkcs8Bytes[offset++] = 0x48;
        pkcs8Bytes[offset++] = (byte) 0x86;
        pkcs8Bytes[offset++] = (byte) 0xF7;
        pkcs8Bytes[offset++] = 0x0D;
        pkcs8Bytes[offset++] = 0x01;
        pkcs8Bytes[offset++] = 0x01;
        pkcs8Bytes[offset++] = 0x01;
        pkcs8Bytes[offset++] = 0x05;
        pkcs8Bytes[offset++] = 0x00;

        // OCTET STRING
        pkcs8Bytes[offset++] = 0x04;
        pkcs8Bytes[offset++] = (byte) 0x82;
        pkcs8Bytes[offset++] = (byte) (pkcs1Len >> 8);
        pkcs8Bytes[offset++] = (byte) pkcs1Len;

        System.arraycopy(pkcs1Bytes, 0, pkcs8Bytes, offset, pkcs1Len);
        return pkcs8Bytes;
    }
}
