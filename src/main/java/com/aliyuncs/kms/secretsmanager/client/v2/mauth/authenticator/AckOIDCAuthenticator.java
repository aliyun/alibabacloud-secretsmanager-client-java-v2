package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils.JwtUtils;

import java.nio.file.Files;
import java.nio.file.Paths;

public class AckOIDCAuthenticator implements Authenticator {

    private final String tokenPath;

    public AckOIDCAuthenticator(String tokenPath) {
        this.tokenPath = tokenPath;
    }

    @Override
    public Identity getIdentity() throws Exception {
        String token = new String(Files.readAllBytes(Paths.get(tokenPath))).trim();
        if (!JwtUtils.isValidJWT(token)) {
            throw new IllegalArgumentException("invalid JWT format");
        }
        Identity identity = new Identity();
        identity.setIdentityType(Identity.IDENTITY_TYPE_JWT);
        identity.setIdentityValue(token);
        return identity;
    }
}
