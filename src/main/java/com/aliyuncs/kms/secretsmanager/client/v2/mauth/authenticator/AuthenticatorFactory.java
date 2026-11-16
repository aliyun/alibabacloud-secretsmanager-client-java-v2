package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

public class AuthenticatorFactory {

    public static Authenticator create(AuthenticatorConfig config) throws Exception {
        if (config.getAuthMethod() == null || config.getAuthMethod().isEmpty()) {
            throw new IllegalArgumentException("invalid config: AuthMethod is required");
        }
        config.validateConfig();
        switch (config.getAuthMethod()) {
            case AuthenticatorConfig.ECS_INSTANCE_IDENTITY:
                return new ECSAuthenticator();
            case AuthenticatorConfig.ACK_OIDC_JWT:
                String tokenPath = config.getTokenPath();
                if (tokenPath == null || tokenPath.isEmpty()) {
                    tokenPath = AuthenticatorConfig.DEFAULT_ACK_TOKEN_PATH;
                }
                return new AckOIDCAuthenticator(tokenPath);
            default:
                throw new IllegalArgumentException("unsupported authentication method: " + config.getAuthMethod());
        }
    }
}
