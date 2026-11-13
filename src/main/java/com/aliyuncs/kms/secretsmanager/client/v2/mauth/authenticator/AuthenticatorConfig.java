package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils.JwtUtils;

public class AuthenticatorConfig {

    public static final String ECS_INSTANCE_IDENTITY = "ECSInstanceIdentity";
    public static final String ACK_OIDC_JWT = "ACKOidcJwt";
    public static final String DEFAULT_ACK_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private String authMethod;
    private String tokenPath;

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getTokenPath() {
        return tokenPath;
    }

    public void setTokenPath(String tokenPath) {
        this.tokenPath = tokenPath;
    }

    public void validateConfig() {
        if (authMethod == null || authMethod.isEmpty()) {
            throw new IllegalArgumentException("AuthMethod is required");
        }
        switch (authMethod) {
            case ECS_INSTANCE_IDENTITY:
                break;
            case ACK_OIDC_JWT:
                if (tokenPath != null && !tokenPath.isEmpty() && !JwtUtils.isValidJWTFile(tokenPath)) {
                    throw new IllegalArgumentException("token file does not exist or has invalid JWT format: " + tokenPath);
                }
                break;
            default:
                throw new IllegalArgumentException("unsupported authentication method: " + authMethod);
        }
    }
}
