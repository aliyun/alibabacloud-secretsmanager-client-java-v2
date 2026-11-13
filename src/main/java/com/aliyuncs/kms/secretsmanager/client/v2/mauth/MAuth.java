package com.aliyuncs.kms.secretsmanager.client.v2.mauth;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator.Authenticator;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator.AuthenticatorConfig;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator.AuthenticatorFactory;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.config.AuthConfig;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger.ExchangerConfig;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger.ExchangeResult;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger.KMSExchanger;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils.ClientKeyUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CommonLogger;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CacheClientConstant;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.ConfigUtils;
import com.aliyun.tea.utils.StringUtils;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.Closeable;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class MAuth implements Closeable {

    public static final long MAX_REMAINING_TIME_HOURS = 48;
    private static final long MILLIS_PER_HOUR = 1000 * 60 * 60;
    private static final long REFRESH_INITIAL_DELAY_MINUTES = 10;
    private static final long REFRESH_PERIOD_MINUTES = 10;

    private Authenticator authenticator;
    private KMSExchanger exchanger;
    private final AuthConfig config;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Map<String, AuthToken> cacheToken = new ConcurrentHashMap<>();
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> refreshTaskFuture;

    public MAuth(AuthConfig config) throws Exception {
        config.validate();
        this.config = config;

        if (AuthConfig.CLIENT_KEY.equals(config.getAuthMethod())) {
            return;
        }

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setAuthMethod(config.getAuthMethod());
        authenticatorConfig.setTokenPath(config.getTokenPath());
        this.authenticator = AuthenticatorFactory.create(authenticatorConfig);

        ExchangerConfig exchangerConfig = new ExchangerConfig();
        exchangerConfig.setExchangerType(ExchangerConfig.EXCHANGER_TYPE_KMS);
        exchangerConfig.setKmsEndpoint(config.getKmsEndpoint());
        exchangerConfig.setAapArn(config.getAapArn());
        exchangerConfig.setCa(config.getCa());
        ExchangerConfig.validateConfig(exchangerConfig);
        this.exchanger = new KMSExchanger(config.getKmsEndpoint(), config.getAapArn(), config.getCa());

        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "mauth-refresh-token-thread");
            t.setDaemon(true);
            return t;
        });

        this.refreshTaskFuture = this.scheduler.scheduleAtFixedRate(() -> {
            try {
                refreshToken();
            } catch (Throwable e) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("Panic in RefreshToken task: {}", e.getMessage(), e);
            }
        }, REFRESH_INITIAL_DELAY_MINUTES, REFRESH_PERIOD_MINUTES, TimeUnit.MINUTES);
    }

    public AuthToken getToken() throws Exception {
        String aapArn = config.getAapArn();
        if (AuthConfig.CLIENT_KEY.equals(config.getAuthMethod())) {
            aapArn = AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY;
        }
        if (StringUtils.isEmpty(aapArn)) {
            aapArn = "";
        }

        lock.readLock().lock();
        try {
            AuthToken cached = cacheToken.get(aapArn);
            if (cached != null && cached.getExpiresAt() != null) {
                long remainingHours = (cached.getExpiresAt().getTime() - System.currentTimeMillis()) / MILLIS_PER_HOUR;
                if (remainingHours > MAX_REMAINING_TIME_HOURS) {
                    return cached;
                }
            }
        } finally {
            lock.readLock().unlock();
        }

        AuthToken newToken;
        try {
            if (AuthConfig.CLIENT_KEY.equals(config.getAuthMethod())) {
                newToken = getClientKeyByLocalFile();
            } else {
                newToken = getTokenFromRemote();
            }
        } catch (Exception e) {
            lock.readLock().lock();
            try {
                AuthToken cached = cacheToken.get(aapArn);
                if (cached != null && cached.getExpiresAt() != null && cached.getExpiresAt().after(new Date())) {
                    CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).warnf("Using cached token for AAP ARN {}, expires at {}", aapArn, cached.getExpiresAt());
                    return cached;
                }
            } finally {
                lock.readLock().unlock();
            }
            if (CommonLogger.isRegistered(CacheClientConstant.MODE_NAME)) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("Failed to get new token for AAP ARN {}: {}", aapArn, e.getMessage(), e);
            }
            throw e;
        }

        lock.writeLock().lock();
        try {
            cacheToken.put(aapArn, newToken);
        } finally {
            lock.writeLock().unlock();
        }
        return newToken;
    }

    public void refreshToken() {
        if (cacheToken.isEmpty()) {
            return;
        }
        Date currentTime = new Date();
        for (Map.Entry<String, AuthToken> entry : cacheToken.entrySet()) {
            String aapArn = entry.getKey();
            AuthToken token = entry.getValue();
            if (token.getExpiresAt() == null) {
                continue;
            }
            long remainingHours = (token.getExpiresAt().getTime() - currentTime.getTime()) / MILLIS_PER_HOUR;
            CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).infof("Token for AAP ARN {} expires at {}, remaining {} hours", aapArn, token.getExpiresAt(), remainingHours);
            if (remainingHours <= MAX_REMAINING_TIME_HOURS) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).infof("Token for AAP ARN {} needs refresh", aapArn);
                try {
                    AuthToken newToken = getToken();
                    if (newToken.getExpiresAt() != null) {
                        long newRemainingHours = (newToken.getExpiresAt().getTime() - currentTime.getTime()) / MILLIS_PER_HOUR;
                        if (newRemainingHours <= MAX_REMAINING_TIME_HOURS) {
                            CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).warnf("Using cached token for AAP ARN {}, expires at {}", aapArn, newToken.getExpiresAt());
                        } else {
                            CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).infof("Successfully refreshed token for AAP ARN {}, expires at {}", aapArn, newToken.getExpiresAt());
                        }
                    }
                } catch (Exception e) {
                    CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("Failed to refresh token for {}: {}", aapArn, e.getMessage(), e);
                }
            }
        }
    }

    public void clearToken() {
        String aapArn = config.getAapArn();
        if (AuthConfig.CLIENT_KEY.equals(config.getAuthMethod())) {
            aapArn = AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY;
        }
        if (StringUtils.isEmpty(aapArn)) {
            aapArn = "";
        }
        lock.writeLock().lock();
        try {
            cacheToken.remove(aapArn);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void close() {
        if (refreshTaskFuture != null) {
            refreshTaskFuture.cancel(false);
        }
        if (scheduler != null) {
            scheduler.shutdown();
        }
    }

    private AuthToken getClientKeyByLocalFile() throws Exception {
        if (StringUtils.isEmpty(config.getClientKeyConfigPath())) {
            throw new IllegalArgumentException("client key config path is not set");
        }
        String configData = ConfigUtils.readFileContent(config.getClientKeyConfigPath());
        Gson gson = new Gson();
        ClientKeyConfig cc = gson.fromJson(configData, ClientKeyConfig.class);
        if (cc == null) {
            throw new IllegalArgumentException("failed to unmarshal client key config");
        }

        String password = config.getClientKeyPassword();
        if (StringUtils.isEmpty(password)) {
            if (StringUtils.isEmpty(config.getClientKeyPasswordPath())) {
                throw new IllegalArgumentException("client key password or password path is not set");
            }
            password = ConfigUtils.readFileContent(config.getClientKeyPasswordPath()).trim();
        }

        ClientKeyUtils.ClientKeyResult result = ClientKeyUtils.extractClientKey(password, cc.getPrivateKeyData());
        AuthToken token = new AuthToken();
        token.setTokenType(AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY);
        token.setTokenKeyId(cc.getKeyId());
        token.setTokenValue(result.getPrivateKeyPem());
        token.setExpiresAt(result.getExpiresAt());
        return token;
    }

    private AuthToken getTokenFromRemote() throws Exception {
        com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator.Identity identity = authenticator.getIdentity();
        ExchangeResult exchangeResult = exchanger.exchangeCredential(identity.getIdentityValue());
        if (!AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY.equals(exchangeResult.getTokenType())) {
            throw new IllegalArgumentException("invalid token type: " + exchangeResult.getTokenType());
        }

        Gson gson = new Gson();
        ClientKeyCredential cc = gson.fromJson(exchangeResult.getTokenValue(), ClientKeyCredential.class);
        if (cc == null) {
            throw new IllegalArgumentException("failed to unmarshal client key credential");
        }

        ClientKeyUtils.ClientKeyResult result = ClientKeyUtils.extractClientKey(cc.getPassword(), cc.getPrivateKeyData());
        AuthToken token = new AuthToken();
        token.setTokenType(exchangeResult.getTokenType());
        token.setTokenKeyId(cc.getClientKeyId());
        token.setTokenValue(result.getPrivateKeyPem());
        token.setExpiresAt(result.getExpiresAt());
        return token;
    }

    private static class ClientKeyConfig {
        @SerializedName("KeyId")
        private String keyId;
        @SerializedName("PrivateKeyData")
        private String privateKeyData;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getPrivateKeyData() {
            return privateKeyData;
        }

        public void setPrivateKeyData(String privateKeyData) {
            this.privateKeyData = privateKeyData;
        }
    }

    private static class ClientKeyCredential {
        @SerializedName("ClientKeyId")
        private String clientKeyId;
        @SerializedName("Password")
        private String password;
        @SerializedName("PrivateKeyData")
        private String privateKeyData;

        public String getClientKeyId() {
            return clientKeyId;
        }

        public void setClientKeyId(String clientKeyId) {
            this.clientKeyId = clientKeyId;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getPrivateKeyData() {
            return privateKeyData;
        }

        public void setPrivateKeyData(String privateKeyData) {
            this.privateKeyData = privateKeyData;
        }
    }
}
