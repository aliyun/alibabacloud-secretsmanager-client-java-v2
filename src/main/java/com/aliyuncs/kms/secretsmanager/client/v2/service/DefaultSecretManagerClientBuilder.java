package com.aliyuncs.kms.secretsmanager.client.v2.service;

import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;
import com.aliyun.credentials.provider.DefaultCredentialsProvider;
import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GetSecretValueRequest;
import com.aliyun.kms20160120.models.GetSecretValueResponse;
import com.aliyun.tea.TeaException;
import com.aliyun.tea.utils.StringUtils;
import com.aliyun.teaopenapi.models.Config;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.CredentialsProperties;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class DefaultSecretManagerClientBuilder extends BaseSecretManagerClientBuilder {

    private List<RegionInfo> regionInfos = new ArrayList<>();

    private final Map<RegionInfo, Config> configMap = new HashMap<>();

    private AlibabaCloudCredentialsProvider provider;

    private BackoffStrategy backoffStrategy;

    private String customConfigFile;

    /**
     * 设置访问阿里云的AccessKey
     *
     * @param accessKeyId     AccessKey ID
     * @param accessKeySecret AccessKey Secret
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder withAccessKey(String accessKeyId, String accessKeySecret) {
        this.provider = CredentialsProviderUtils.withAccessKey(accessKeyId, accessKeySecret);
        return this;
    }

    /**
     * 设置凭证
     *
     * @param provider 凭证
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder withCredentialsProvider(AlibabaCloudCredentialsProvider provider) {
        this.provider = provider;
        return this;
    }

    /**
     * 指定调用地域Id
     *
     * @param regionId 调用地域Id
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder addRegion(String regionId) {
        return addRegion(new RegionInfo(regionId));
    }

    /**
     * 指定调用地域信息
     *
     * @param regionInfo 调用地域信息
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder addRegion(RegionInfo regionInfo) {
        this.regionInfos.add(regionInfo);
        return this;
    }

    /**
     * 指定多个调用地域Id
     *
     * @param regionIds 多个调用地域Id
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder withRegion(String... regionIds) {
        for (String regionId : regionIds) {
            addRegion(new RegionInfo(regionId));
        }
        return this;
    }


    /**
     * 设置退避策略
     *
     * @param backoffStrategy 退避策略
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder withBackoffStrategy(BackoffStrategy backoffStrategy) {
        this.backoffStrategy = backoffStrategy;
        return this;
    }

    /**
     * 添加配置信息
     *
     * @param config 配置信息
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder addConfig(Config config) {
        RegionInfo regionInfo = new RegionInfo(config.getRegionId(), config.getEndpoint());
        this.configMap.put(regionInfo, config);
        regionInfos.add(regionInfo);
        return this;
    }

    /**
     * 设置自定义配置文件
     *
     * @param customConfigFile 自定义配置文件路径
     * @return DefaultSecretManagerClientBuilder实例
     */
    public DefaultSecretManagerClientBuilder withCustomConfigFile(String customConfigFile) {
        this.customConfigFile = customConfigFile;
        return this;
    }

    /**
     * 构建SecretManagerClient实例
     *
     * @return SecretManagerClient实例
     * @throws CacheSecretException 缓存凭据异常
     */
    public SecretManagerClient build() throws CacheSecretException {
        return new DefaultSecretManagerClient();
    }

    class DefaultSecretManagerClient implements SecretManagerClient {

        private final Map<RegionInfo, Client> clientMap = new HashMap<>();

        private final ThreadPoolExecutor pool = new ThreadPoolExecutor(
                Runtime.getRuntime().availableProcessors(),
                Runtime.getRuntime().availableProcessors() * 2,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy()
        );

        {
            pool.allowCoreThreadTimeOut(true);
        }

        public GetSecretValueResponse getSecretValue(GetSecretValueRequest req) throws Exception {
            List<Future<GetSecretValueResponse>> futures = new ArrayList<>();
            CountDownLatch count = null;
            AtomicInteger finished = null;
            for (int i = 0; i < regionInfos.size(); i++) {
                if (i == 0) {
                    try {
                        return getSecretValue(regionInfos.get(i), req);
                    } catch (Exception e) {
                        CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:getSecretValue", e);
                        if (!BackoffUtils.judgeNeedRecoveryException(e)) {
                            throw e;
                        }

                        count = new CountDownLatch(1);
                        finished = new AtomicInteger(regionInfos.size());
                    }
                }
                GetSecretValueRequest request = new GetSecretValueRequest();
                request.setSecretName(req.getSecretName());
                request.setVersionStage(req.getVersionStage());
                request.setFetchExtendedConfig(true);
                Future<GetSecretValueResponse> future = pool.submit(new RetryGetSecretValueTask(request, regionInfos.get(i), count, finished));
                futures.add(future);
            }

            GetSecretValueResponse getSecretValueResponse;
            try {
                count.await(CacheClientConstant.REQUEST_WAITING_TIME, TimeUnit.MILLISECONDS);
                for (Future<GetSecretValueResponse> future : futures) {
                    try {
                        if (!future.isDone()) {
                            future.cancel(true);
                        } else {
                            getSecretValueResponse = future.get();
                            if (getSecretValueResponse != null) {
                                return getSecretValueResponse;
                            }
                        }
                    } catch (InterruptedException | ExecutionException e) {
                        CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:asyncGetSecretValue", e);
                    }
                }
            } catch (TeaException e) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:retryGetSecretValueTask", e);
                throw e;
            } catch (Exception e) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:retryGetSecretValueTask", e);
                throw new TeaException(e.getMessage(), e);
            } finally {
                if (count.getCount() > 0) {
                    count.countDown();
                }
            }
            throw new TeaException(new HashMap<String, Object>() {{
                put("code", CacheClientConstant.SDK_READ_TIMEOUT);
                put("message", String.format("refreshSecretTask fail with secretName[%s]", req.getSecretName()));
            }});
        }

        @Override
        public void close() {
            if (!pool.isShutdown()) {
                pool.shutdown();
                try {
                    if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                        pool.shutdownNow();
                        if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                            CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:close",
                                    "Thread pool did not terminate");
                        }
                    }
                } catch (InterruptedException ie) {
                    pool.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
        }

        public GetSecretValueResponse getSecretValue(RegionInfo regionInfo, GetSecretValueRequest req) throws Exception {
            return getClient(regionInfo).getSecretValue(req);
        }

        private synchronized Client getClient(RegionInfo regionInfo) throws Exception {
            Client client = clientMap.get(regionInfo);
            if (client != null) {
                return client;
            }
            client = buildKMSClient(regionInfo);
            clientMap.put(regionInfo, client);
            return client;
        }

        private Client buildKMSClient(RegionInfo regionInfo) throws Exception {
            Config config = configMap.get(regionInfo);
            if (config == null) {
                config = new Config();
                if (!StringUtils.isEmpty(regionInfo.getEndpoint())) {
                    config.setEndpoint(regionInfo.getEndpoint());
                    if (regionInfo.getEndpoint().endsWith(CacheClientConstant.INSTANCE_GATEWAY_DOMAIN_SUFFIX)) {
                        if (!StringUtils.isEmpty(regionInfo.getCaFilePath())) {
                            config.setCa(ConfigUtils.readFileContent(regionInfo.getCaFilePath()));
                        } else {
                            String caContent = PrivateCaUtils.REGION_ID_AND_CA_MAP.get(regionInfo.getRegionId());
                            if (caContent == null) {
                                throw new IllegalArgumentException(
                                        String.format("cannot find the built-in ca certificate for region[%s], please provide the caFilePath parameter.",
                                                regionInfo.getRegionId()));
                            }
                            config.setCa(caContent);
                        }
                    }
                } else if (regionInfo.getVpc()) {
                    config.setEndpoint(KmsEndpointUtils.getVPCEndpoint(regionInfo.getRegionId()));
                } else {
                    config.setEndpoint(KmsEndpointUtils.getEndPoint(regionInfo.getRegionId()));
                }
                provider = provider == null ? new DefaultCredentialsProvider() : provider;
                config.setCredential(new com.aliyun.credentials.Client(provider));
                config.protocol = CacheClientConstant.DEFAULT_PROTOCOL;
            }
            if (config.ca != null) {
                config.setUserAgent(String.format("%s/%s %s_ca_expiration_utc_date/%s", UserAgentManager.getUserAgent(), UserAgentManager.getProjectVersion(), regionInfo.getRegionId(), PrivateCaUtils.getCaExpirationUtcDate(config.ca)));
            } else {
                config.setUserAgent(String.format("%s/%s", UserAgentManager.getUserAgent(), UserAgentManager.getProjectVersion()));
            }
            return new Client(config);
        }

        public void init() throws CacheSecretException {
            initFromConfigFile();
            initFromEnv();
            checkRegionInfo();
            UserAgentManager.registerUserAgent(CacheClientConstant.USER_AGENT_OF_SECRETS_MANAGER_V2_JAVA, 0, CacheClientConstant.PROJECT_VERSION);
            if (backoffStrategy == null) {
                backoffStrategy = new FullJitterBackoffStrategy();
            }
            backoffStrategy.init();
            if (regionInfos.size() > 1) {
                regionInfos = regionInfos.stream().distinct().collect(Collectors.toList());
            }
            if (regionInfos.size() > 1) {
                regionInfos = sortRegionInfos(regionInfos);
            }
            regionInfos.forEach(regionInfo -> {
                try {
                    getClient(regionInfo);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }

        private void checkRegionInfo() {
            if (regionInfos.isEmpty()) {
                throw new IllegalArgumentException("The param[regionInfo] is needed");
            }
        }

        private void initFromEnv() {
            Map<String, String> envMap = System.getenv();
            initKmsRegionsFromEnv(envMap);
            initCredentialsProviderFromEnv(envMap);
        }

        private void initCredentialsProviderFromEnv(Map<String, String> envMap) {
            AlibabaCloudCredentialsProvider provider = CredentialsProviderUtils.initCredentialsProviderFromEnv(envMap);
            if (provider != null) {
                withCredentialsProvider(provider);
            }
        }

        private void initKmsRegionsFromEnv(Map<String, String> envMap) {
            Properties properties = new Properties();
            properties.putAll(envMap);
            regionInfos.addAll(CredentialsProviderUtils.initKmsRegions(properties, CacheClientConstant.SOURCE_TYPE_ENV));
        }

        private void initFromConfigFile() {
            CredentialsProperties credentialsProperties = CredentialsPropertiesUtils.loadCredentialsProperties(customConfigFile);
            if (credentialsProperties != null) {
                if (credentialsProperties.getProvider() != null) {
                    AlibabaCloudCredentialsProvider provider = credentialsProperties.getProvider();
                    withCredentialsProvider(provider);
                }
                regionInfos.addAll(credentialsProperties.getRegionInfoList());
            }
        }

        class RetryGetSecretValueTask implements Callable<GetSecretValueResponse> {
            final private GetSecretValueRequest req;
            final private RegionInfo regionInfo;
            final private CountDownLatch countDownLatch;
            final private AtomicInteger finished;

            public RetryGetSecretValueTask(GetSecretValueRequest req, RegionInfo regionInfo, CountDownLatch countDownLatch, AtomicInteger finished) {
                this.req = req;
                this.regionInfo = regionInfo;
                this.countDownLatch = countDownLatch;
                this.finished = finished;
            }

            @Override
            public GetSecretValueResponse call() throws Exception {
                try {
                    GetSecretValueResponse resp = retryGetSecretValue(req, regionInfo);
                    countDownLatch.countDown();
                    return resp;
                } catch (Exception e) {
                    CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:retryGetSecretValue call", e);
                    return null;
                } finally {
                    if (finished.decrementAndGet() == 0) {
                        countDownLatch.countDown();
                    }
                }
            }

            private GetSecretValueResponse retryGetSecretValue(GetSecretValueRequest req, RegionInfo regionInfo) throws Exception {
                int retryTimes = 0;
                Exception lastException = null;
                while (true) {
                    if (countDownLatch.getCount() == 0) {
                        return null;
                    }
                    long waitTimeExponential = backoffStrategy.getWaitTimeExponential(retryTimes);
                    if (waitTimeExponential < 0) {
                        throw new TeaException("Times limit exceeded", lastException);
                    }
                    if (waitTimeExponential > 0) {
                        try {
                            Thread.sleep(waitTimeExponential);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw e;
                        }
                    }
                    try {
                        return getSecretValue(regionInfo, req);
                    } catch (Exception e) {
                        lastException = e;
                        CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).errorf("action:getSecretValue regionInfo:{} retryTimes:{} ", regionInfo, retryTimes, e);
                        if (!BackoffUtils.judgeNeedRecoveryException(e)) {
                            throw e;
                        }
                    }
                    retryTimes++;
                }
            }
        }
    }

    private List<RegionInfo> sortRegionInfos(List<RegionInfo> regionInfos) {
        List<RegionInfoExtend> regionInfoExtends = new ArrayList<>();
        for (RegionInfo regionInfo : regionInfos) {
            double pingDelay;
            if (!StringUtils.isEmpty(regionInfo.getEndpoint())) {
                pingDelay = PingUtils.ping(regionInfo.getEndpoint());
            } else if (regionInfo.getVpc()) {
                pingDelay = PingUtils.ping(KmsEndpointUtils.getVPCEndpoint(regionInfo.getRegionId()));
            } else {
                pingDelay = PingUtils.ping(KmsEndpointUtils.getEndPoint(regionInfo.getRegionId()));
            }
            RegionInfoExtend regionInfoExtend = new RegionInfoExtend(regionInfo);
            regionInfoExtend.setReachable(pingDelay >= 0);
            regionInfoExtend.setElapsed(pingDelay >= 0 ? pingDelay : Double.MAX_VALUE);
            regionInfoExtends.add(regionInfoExtend);
        }
        return regionInfoExtends.stream().sorted(Comparator.comparing((RegionInfoExtend regionInfoExtend) -> !regionInfoExtend.getReachable())
                        .thenComparing(RegionInfoExtend::getElapsed))
                .map(regionInfoExtend -> new RegionInfo(regionInfoExtend.getRegionId(), regionInfoExtend.getVpc(), regionInfoExtend.getEndpoint(), regionInfoExtend.getCaFilePath()))
                .collect(Collectors.toList());
    }

    static class RegionInfoExtend {

        private boolean reachable;
        private double elapsed;
        private final String regionId;
        private final boolean vpc;
        private final String endpoint;
        private final String caFilePath;

        public RegionInfoExtend(RegionInfo regionInfo) {
            this.regionId = regionInfo.getRegionId();
            this.vpc = regionInfo.getVpc();
            this.endpoint = regionInfo.getEndpoint();
            this.caFilePath = regionInfo.getCaFilePath();
        }

        public String getRegionId() {
            return regionId;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public boolean getVpc() {
            return this.vpc;
        }

        public boolean getReachable() {
            return this.reachable;
        }

        public void setReachable(boolean reachable) {
            this.reachable = reachable;
        }

        public double getElapsed() {
            return this.elapsed;
        }

        public void setElapsed(double elapsed) {
            this.elapsed = elapsed;
        }

        public String getCaFilePath() {
            return caFilePath;
        }
    }

}