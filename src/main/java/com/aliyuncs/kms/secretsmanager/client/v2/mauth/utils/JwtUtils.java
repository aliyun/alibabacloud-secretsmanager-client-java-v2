package com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class JwtUtils {

    private static final Gson GSON = new Gson();

    public static boolean isValidJWT(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        for (int i = 0; i < 2; i++) {
            String padded = addPadding(parts[i]);
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(padded);
                Map<String, Object> json = GSON.fromJson(new String(decoded), new TypeToken<Map<String, Object>>() {}.getType());
                if (json == null) {
                    return false;
                }
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    public static Map<String, Object> parseJWTClaims(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("invalid JWT format: not 3 parts");
        }
        String paddedPayload = addPadding(parts[1]);
        byte[] decoded = Base64.getUrlDecoder().decode(paddedPayload);
        return GSON.fromJson(new String(decoded), new TypeToken<Map<String, Object>>() {}.getType());
    }

    public static boolean isValidJWTFile(String filePath) {
        try {
            if (!Files.exists(Paths.get(filePath))) {
                return false;
            }
            String token = new String(Files.readAllBytes(Paths.get(filePath))).trim();
            return isValidJWT(token);
        } catch (Exception e) {
            return false;
        }
    }

    public static Date getJWTExpiration(String token) throws Exception {
        Map<String, Object> claims = parseJWTClaims(token);
        Object expObj = claims.get("exp");
        if (expObj == null) {
            throw new IllegalArgumentException("JWT does not contain 'exp' claim");
        }
        long exp;
        if (expObj instanceof Number) {
            exp = ((Number) expObj).longValue();
        } else {
            exp = Long.parseLong(expObj.toString());
        }
        return new Date(exp * 1000);
    }

    private static String addPadding(String s) {
        int len = s.length() % 4;
        if (len == 2) {
            return s + "==";
        } else if (len == 3) {
            return s + "=";
        }
        return s;
    }
}
