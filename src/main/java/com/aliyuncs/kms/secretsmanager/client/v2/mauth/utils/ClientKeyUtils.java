package com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;

public class ClientKeyUtils {

    public static class ClientKeyResult {
        private final String privateKeyPem;
        private final Date expiresAt;

        public ClientKeyResult(String privateKeyPem, Date expiresAt) {
            this.privateKeyPem = privateKeyPem;
            this.expiresAt = expiresAt;
        }

        public String getPrivateKeyPem() {
            return privateKeyPem;
        }

        public Date getExpiresAt() {
            return expiresAt;
        }
    }

    public static ClientKeyResult extractClientKey(String password, String privateKeyData) throws Exception {
        byte[] pkcs12Bytes = Base64.getDecoder().decode(privateKeyData);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(pkcs12Bytes), password.toCharArray());

        String alias = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                alias = a;
                break;
            }
        }
        if (alias == null) {
            throw new IllegalArgumentException("no key entry found in PKCS12");
        }

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("no certificate found in PKCS12");
        }
        X509Certificate x509Cert = (X509Certificate) cert;

        String privateKeyPem = convertToPem(privateKey);
        Date expiresAt = x509Cert.getNotAfter();

        return new ClientKeyResult(privateKeyPem, expiresAt);
    }

    private static String convertToPem(PrivateKey privateKey) {
        String type = "PRIVATE KEY";
        String base64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length())).append("\n");
        }
        sb.append("-----END ").append(type).append("-----");
        return sb.toString();
    }
}
