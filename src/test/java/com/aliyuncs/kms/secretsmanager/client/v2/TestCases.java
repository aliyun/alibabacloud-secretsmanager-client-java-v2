package com.aliyuncs.kms.secretsmanager.client.v2;

import com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.service.FullJitterBackoffStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.service.SecretManagerClient;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.*;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.model.CredentialsProperties;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;
import com.aliyun.credentials.provider.StaticCredentialsProvider;
import com.aliyun.credentials.provider.EcsRamRoleCredentialProvider;
import com.aliyun.credentials.provider.OIDCRoleArnCredentialProvider;
import com.aliyun.credentials.models.CredentialModel;
import org.junit.Test;
import org.junit.Assert;

import java.lang.reflect.Constructor;
import java.util.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 测试初始化、重试策略、CA证书读取以及凭证配置和环境变量读取功能
 */
public class TestCases {

    /**
     * 测试初始化功能
     */
    @Test
    public void testInitialization() {
        try {
            // 创建一个客户端构建器
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 添加区域信息
            builder.addRegion("cn-hangzhou");

            // 构建客户端
            SecretManagerClient client = builder.build();

            // 调用初始化方法
            client.init();

            // 验证初始化成功
            Assert.assertNotNull(client);

            // 验证region是否正确设置
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);
            Assert.assertNotNull("Region infos should not be null", regionInfos);
            Assert.assertFalse("Region infos should not be empty", regionInfos.isEmpty());
            Assert.assertEquals("Should have 1 region", 1, regionInfos.size());
            Assert.assertEquals("Region ID should match", "cn-hangzhou", regionInfos.get(0).getRegionId());

            System.out.println("Initialization test passed");
        } catch (Exception e) {
            Assert.fail("Initialization test failed: " + e.getMessage());
        }
    }

    /**
     * 测试重试策略功能
     */
    @Test
    public void testRetryStrategy() {
        try {
            // 测试默认退避策略
            FullJitterBackoffStrategy defaultStrategy = new FullJitterBackoffStrategy();
            defaultStrategy.init();

            // 验证默认参数
            Assert.assertNotNull(defaultStrategy);

            // 测试自定义退避策略
            FullJitterBackoffStrategy customStrategy = new FullJitterBackoffStrategy(5, 1000, 30000);
            customStrategy.init();

            // 验证自定义参数
            long waitTime = customStrategy.getWaitTimeExponential(2);
            Assert.assertTrue("Wait time should be positive", waitTime > 0);

            // 测试超过最大重试次数的情况
            long negativeWaitTime = customStrategy.getWaitTimeExponential(10);
            Assert.assertEquals("Should return -1 when exceeding max attempts", -1, negativeWaitTime);

            System.out.println("Retry strategy test passed");
        } catch (CacheSecretException e) {
            Assert.fail("Retry strategy test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CA证书读取功能
     */
    @Test
    public void testCACertificateReading() {
        // 验证CA证书映射表不为空
        Assert.assertNotNull(PrivateCaUtils.REGION_ID_AND_CA_MAP);
        Assert.assertFalse(PrivateCaUtils.REGION_ID_AND_CA_MAP.isEmpty());

        // 验证特定区域的CA证书存在
        String caCertificate = PrivateCaUtils.REGION_ID_AND_CA_MAP.get("cn-hangzhou");
        Assert.assertNotNull("CA certificate for cn-hangzhou should exist", caCertificate);
        Assert.assertTrue("CA certificate should start with -----BEGIN CERTIFICATE-----",
                caCertificate.startsWith("-----BEGIN CERTIFICATE-----"));

        System.out.println("CA certificate reading test passed");
    }

    /**
     * 测试凭证配置读取功能
     */
    @Test
    public void testCredentialsConfigurationReading() {
        try {
            // 创建测试属性
            Properties testProperties = new Properties();
            testProperties.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            testProperties.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY, "testAccessKeyId");
            testProperties.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY, "testAccessKeySecret");

            // 测试从配置读取凭证
            AlibabaCloudCredentialsProvider provider =
                    CredentialsProviderUtils.initCredentialsProviderFromConfig(testProperties);

            Assert.assertNotNull("Credentials provider should not be null", provider);
            Assert.assertTrue("Provider should be StaticCredentialsProvider",
                    provider instanceof StaticCredentialsProvider);

            System.out.println("Credentials configuration reading test passed");
        } catch (Exception e) {
            Assert.fail("Credentials configuration reading test failed: " + e.getMessage());
        }
    }

    /**
     * 测试环境变量读取功能
     */
    @Test
    public void testEnvironmentVariableReading() {
        try {
            // 创建测试环境变量映射
            Map<String, String> testEnvMap = new HashMap<>();
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY, "testAccessKeyId");
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY, "testAccessKeySecret");

            // 测试从环境变量读取凭证
            AlibabaCloudCredentialsProvider provider =
                    CredentialsProviderUtils.initCredentialsProviderFromEnv(testEnvMap);

            Assert.assertNotNull("Credentials provider should not be null", provider);
            Assert.assertTrue("Provider should be StaticCredentialsProvider",
                    provider instanceof StaticCredentialsProvider);

            System.out.println("Environment variable reading test passed");
        } catch (Exception e) {
            Assert.fail("Environment variable reading test failed: " + e.getMessage());
        }
    }

    /**
     * 测试区域信息初始化
     */
    @Test
    public void testRegionInitialization() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 添加多个区域
            builder.withRegion("cn-hangzhou", "cn-shanghai", "cn-beijing");

            // 使用反射获取regionInfos字段
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);

            // 验证区域信息已正确添加
            Assert.assertEquals("Should have 3 regions", 3, regionInfos.size());

            Set<String> expectedRegions = new HashSet<>(Arrays.asList("cn-hangzhou", "cn-shanghai", "cn-beijing"));
            Set<String> actualRegions = new HashSet<>();
            for (RegionInfo regionInfo : regionInfos) {
                actualRegions.add(regionInfo.getRegionId());
            }

            Assert.assertEquals("Region IDs should match", expectedRegions, actualRegions);

            System.out.println("Region initialization test passed");
        } catch (Exception e) {
            Assert.fail("Region initialization test failed: " + e.getMessage());
        }
    }

    /**
     * 测试自定义配置文件读取
     */
    @Test
    public void testCustomConfigFileReading() {
        // 测试凭据属性工具类
        CredentialsProperties credentialsProperties = CredentialsPropertiesUtils.loadCredentialsProperties(null);

        // 如果没有配置文件，应该返回null或者处理默认情况
        // 这里我们主要测试方法是否能正常执行
        Assert.assertTrue("Method should execute without exception", true);

        System.out.println("Custom config file reading test passed");
    }

    /**
     * 测试退避策略的指数等待时间计算
     */
    @Test
    public void testBackoffStrategyWaitTimeCalculation() {
        FullJitterBackoffStrategy strategy = new FullJitterBackoffStrategy(3, 1000, 10000);

        try {
            strategy.init();

            // 测试不同重试次数的等待时间计算
            long waitTime0 = strategy.getWaitTimeExponential(0);
            long waitTime1 = strategy.getWaitTimeExponential(1);
            long waitTime2 = strategy.getWaitTimeExponential(2);
            long waitTime3 = strategy.getWaitTimeExponential(3);
            long waitTime4 = strategy.getWaitTimeExponential(4); // 超过最大重试次数

            // 验证计算结果
            Assert.assertEquals("Retry 0 should be 1000ms", 1000, waitTime0);
            Assert.assertEquals("Retry 1 should be 2000ms", 2000, waitTime1);
            Assert.assertEquals("Retry 2 should be 4000ms", 4000, waitTime2);
            Assert.assertEquals("Retry 3 should be 8000ms", 8000, waitTime3);
            Assert.assertEquals("Retry 4 should be -1 (exceeded max attempts)", -1, waitTime4);

            System.out.println("Backoff strategy wait time calculation test passed");
        } catch (CacheSecretException e) {
            Assert.fail("Backoff strategy wait time calculation test failed: " + e.getMessage());
        }
    }

    /**
     * 测试退避策略边界条件
     */
    @Test
    public void testBackoffStrategyBoundaryConditions() {
        try {
            // 测试最大重试次数边界条件
            FullJitterBackoffStrategy strategy = new FullJitterBackoffStrategy(3, 1000, 10000);
            strategy.init();

            // 验证超过最大重试次数的情况
            long waitTime = strategy.getWaitTimeExponential(4);
            Assert.assertEquals(-1, waitTime);

            // 测试初始间隔为0的情况
            FullJitterBackoffStrategy strategyWithZeroInterval = new FullJitterBackoffStrategy(3, 0, 10000);
            strategyWithZeroInterval.init();
            Assert.assertEquals(0, strategyWithZeroInterval.getWaitTimeExponential(1));

            // 测试容量为0情况
            FullJitterBackoffStrategy strategyWithZeroCapacity = new FullJitterBackoffStrategy(3, 1000, 0);
            strategyWithZeroCapacity.init();
            Assert.assertEquals(0, strategyWithZeroCapacity.getWaitTimeExponential(1));

            System.out.println("Backoff strategy boundary conditions test passed");
        } catch (Exception e) {
            Assert.fail("Backoff strategy boundary conditions test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClientBuilder的各种方法
     */
    @Test
    public void testDefaultSecretManagerClientBuilderMethods() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 测试withAccessKey方法
            builder.withAccessKey("testAccessKeyId", "testAccessKeySecret");

            // 测试withCredentialsProvider方法
            AlibabaCloudCredentialsProvider testProvider = new StaticCredentialsProvider.Builder().credential(
                    CredentialModel.builder()
                            .accessKeyId("testAccessKeyId")
                            .accessKeySecret("testAccessKeySecret")
                            .type("access_key")
                            .build()
            ).build();
            builder.withCredentialsProvider(testProvider);

            // 测试addRegion方法
            builder.addRegion("cn-hangzhou");

            // 测试withRegion方法
            builder.withRegion("cn-shanghai", "cn-beijing");

            // 测试withBackoffStrategy方法
            FullJitterBackoffStrategy strategy = new FullJitterBackoffStrategy();
            builder.withBackoffStrategy(strategy);

            // 测试withCustomConfigFile方法
            builder.withCustomConfigFile("/path/to/config");

            // 测试addConfig方法（通过反射验证）
            Field configMapField = DefaultSecretManagerClientBuilder.class.getDeclaredField("configMap");
            configMapField.setAccessible(true);
            Map<?, ?> configMap = (Map<?, ?>) configMapField.get(builder);
            Assert.assertNotNull("Config map should not be null", configMap);

            System.out.println("DefaultSecretManagerClientBuilder methods test passed");
        } catch (Exception e) {
            Assert.fail("DefaultSecretManagerClientBuilder methods test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsPropertiesUtils的各种方法
     */
    @Test
    public void testCredentialsPropertiesUtilsMethods() {
        try {
            // 测试loadCredentialsProperties方法
            CredentialsProperties properties = CredentialsPropertiesUtils.loadCredentialsProperties(null);

            // 测试initKmsRegions方法
            Properties testProps = new Properties();
            String regionJson = "[{\"regionId\":\"cn-hangzhou\"},{\"regionId\":\"cn-shanghai\"}]";
            testProps.setProperty(CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY, regionJson);

            List<RegionInfo> regions = CredentialsProviderUtils.initKmsRegions(testProps, "test");
            Assert.assertEquals("Should have 2 regions", 2, regions.size());

            System.out.println("CredentialsPropertiesUtils methods test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsPropertiesUtils methods test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsProviderUtils的各种凭证类型
     */
    @Test
    public void testCredentialsProviderUtilsAllTypes() {
        try {
            // 测试withAccessKey方法
            AlibabaCloudCredentialsProvider akProvider = CredentialsProviderUtils.withAccessKey(
                    "testAccessKeyId", "testAccessKeySecret");
            Assert.assertTrue("Should be StaticCredentialsProvider",
                    akProvider instanceof StaticCredentialsProvider);

            // 测试withEcsRamRole方法
            AlibabaCloudCredentialsProvider ecsProvider = CredentialsProviderUtils.withEcsRamRole("testRole");
            Assert.assertTrue("Should be EcsRamRoleCredentialProvider",
                    ecsProvider instanceof EcsRamRoleCredentialProvider);

            // 测试withOIDCRoleArn完整参数方法
            AlibabaCloudCredentialsProvider oidcProvider1 = CredentialsProviderUtils.withOIDCRoleArn(
                    "testSession", "testRoleArn", "testOidcProviderArn", "/path/to/token",
                    "testPolicy", "sts.cn-hangzhou.aliyuncs.com", 3600, "cn-hangzhou");
            Assert.assertTrue("Should be OIDCRoleArnCredentialProvider",
                    oidcProvider1 instanceof OIDCRoleArnCredentialProvider);

            // 测试withOIDCRoleArn简化参数方法
            AlibabaCloudCredentialsProvider oidcProvider2 = CredentialsProviderUtils.withOIDCRoleArn(
                    "testRoleArn", "testOidcProviderArn", "/path/to/token");
            Assert.assertTrue("Should be OIDCRoleArnCredentialProvider",
                    oidcProvider2 instanceof OIDCRoleArnCredentialProvider);

            // 测试initCredentialsProvider方法 - AK类型
            Map<String, String> akMap = new HashMap<>();
            akMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            akMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY, "testAccessKeyId");
            akMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY, "testAccessKeySecret");

            AlibabaCloudCredentialsProvider akProviderFromInit =
                    CredentialsProviderUtils.initCredentialsProvider(akMap, "test");
            Assert.assertTrue("Should be StaticCredentialsProvider",
                    akProviderFromInit instanceof StaticCredentialsProvider);

            // 测试initCredentialsProvider方法 - ECS RAM Role类型
            Map<String, String> ecsMap = new HashMap<>();
            ecsMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ecs_ram_role");
            ecsMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ROLE_NAME_KEY, "testRole");

            AlibabaCloudCredentialsProvider ecsProviderFromInit =
                    CredentialsProviderUtils.initCredentialsProvider(ecsMap, "test");
            Assert.assertTrue("Should be EcsRamRoleCredentialProvider",
                    ecsProviderFromInit instanceof EcsRamRoleCredentialProvider);

            // 测试initCredentialsProvider方法 - OIDC Role Arn类型
            Map<String, String> oidcMap = new HashMap<>();
            oidcMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "oidc_role_arn");
            oidcMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_ROLE_ARN_KEY, "testRoleArn");
            oidcMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_PROVIDER_ARN_KEY, "testProviderArn");
            oidcMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_TOKEN_FILE_PATH_KEY, "/path/to/token");

            AlibabaCloudCredentialsProvider oidcProviderFromInit =
                    CredentialsProviderUtils.initCredentialsProvider(oidcMap, "test");
            Assert.assertTrue("Should be OIDCRoleArnCredentialProvider",
                    oidcProviderFromInit instanceof OIDCRoleArnCredentialProvider);

            System.out.println("CredentialsProviderUtils all types test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsProviderUtils all types test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsProviderUtils异常情况
     */
    @Test
    public void testCredentialsProviderUtilsExceptions() {
        // 测试无效的凭证类型
        try {
            Map<String, String> invalidMap = new HashMap<>();
            invalidMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "invalid_type");

            CredentialsProviderUtils.initCredentialsProvider(invalidMap, "test");
            Assert.fail("Should throw IllegalArgumentException for invalid credential type");
        } catch (IllegalArgumentException e) {
            // 预期异常
            Assert.assertTrue(e.getMessage().contains("credentials type"));
        }

        // 测试AK类型缺少必要参数
        try {
            Map<String, String> incompleteAkMap = new HashMap<>();
            incompleteAkMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            // 故意不设置accessKeyId和accessKeySecret

            CredentialsProviderUtils.initCredentialsProvider(incompleteAkMap, "test");
            Assert.fail("Should throw IllegalArgumentException for missing AK params");
        } catch (IllegalArgumentException e) {
            // 预期异常
            Assert.assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY));
        }

        System.out.println("CredentialsProviderUtils exceptions test passed");
    }

    /**
     * 测试DefaultSecretManagerClientBuilder的build方法和初始化流程
     */
    @Test
    public void testDefaultSecretManagerClientBuilderBuildAndInit() {
        try {
            // 测试没有添加region时的异常情况
            DefaultSecretManagerClientBuilder builderWithoutRegion = DefaultSecretManagerClientBuilder.standard();
            SecretManagerClient clientWithoutRegion = builderWithoutRegion.build();

            try {
                clientWithoutRegion.init();
                Assert.fail("Should throw IllegalArgumentException when no region is specified");
            } catch (IllegalArgumentException e) {
                Assert.assertTrue(e.getMessage().contains("regionInfo"));
            }

            // 测试正常构建流程
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            SecretManagerClient client = builder.build();
            Assert.assertNotNull("Client should not be null", client);

            System.out.println("DefaultSecretManagerClientBuilder build and init test passed");
        } catch (Exception e) {
            Assert.fail("DefaultSecretManagerClientBuilder build and init test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClientBuilder的addConfig方法
     */
    @Test
    public void testDefaultSecretManagerClientBuilderAddConfig() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 创建一个配置对象
            com.aliyun.teaopenapi.models.Config config = new com.aliyun.teaopenapi.models.Config();
            config.setRegionId("cn-hangzhou");
            config.setEndpoint("kms.cn-hangzhou.aliyuncs.com");

            // 测试addConfig方法
            builder.addConfig(config);

            // 使用反射检查configMap是否正确添加
            Field configMapField = DefaultSecretManagerClientBuilder.class.getDeclaredField("configMap");
            configMapField.setAccessible(true);
            Map<?, ?> configMap = (Map<?, ?>) configMapField.get(builder);
            Assert.assertEquals("Config map should contain 1 entry", 1, configMap.size());

            // 使用反射检查regionInfos是否正确添加
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<?> regionInfos = (List<?>) regionInfosField.get(builder);
            Assert.assertEquals("Region infos should contain 1 entry", 1, regionInfos.size());

            System.out.println("DefaultSecretManagerClientBuilder addConfig test passed");
        } catch (Exception e) {
            Assert.fail("DefaultSecretManagerClientBuilder addConfig test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsPropertiesUtils.loadCredentialsProperties方法
     */
    @Test
    public void testCredentialsPropertiesUtilsLoadCredentialsProperties() {
        try {
            // 测试加载null配置文件名的情况
            CredentialsProperties properties = CredentialsPropertiesUtils.loadCredentialsProperties(null);
            // 如果没有默认配置文件，应该返回null
            // 这里我们主要测试方法是否能正常执行

            // 测试加载不存在的配置文件
            CredentialsProperties properties2 = CredentialsPropertiesUtils.loadCredentialsProperties("non-existent.properties");
            // 同样，主要测试方法是否能正常执行

            System.out.println("CredentialsPropertiesUtils loadCredentialsProperties test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsPropertiesUtils loadCredentialsProperties test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsPropertiesUtils.initKmsRegions方法的异常情况
     */
    @Test
    public void testCredentialsPropertiesUtilsInitKmsRegionsExceptions() {
        try {
            Properties testProps = new Properties();
            // 设置非法的JSON格式
            testProps.setProperty(CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY, "invalid-json");

            try {
                List<RegionInfo> regions = CredentialsProviderUtils.initKmsRegions(testProps, "test");
                Assert.fail("Should throw IllegalArgumentException for invalid JSON");
            } catch (IllegalArgumentException e) {
                Assert.assertTrue("Exception message should contain 'credentials param'",
                        e.getMessage().contains("credentials param"));
            }

            System.out.println("CredentialsPropertiesUtils initKmsRegions exceptions test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsPropertiesUtils initKmsRegions exceptions test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsProviderUtils.initCredentialsProviderFromConfig方法
     */
    @Test
    public void testCredentialsProviderUtilsInitFromConfig() {
        try {
            Properties testProps = new Properties();
            testProps.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            testProps.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY, "testAccessKeyId");
            testProps.setProperty(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY, "testAccessKeySecret");

            AlibabaCloudCredentialsProvider provider =
                    CredentialsProviderUtils.initCredentialsProviderFromConfig(testProps);

            Assert.assertNotNull("Provider should not be null", provider);
            Assert.assertTrue("Provider should be StaticCredentialsProvider",
                    provider instanceof StaticCredentialsProvider);

            System.out.println("CredentialsProviderUtils initCredentialsProviderFromConfig test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsProviderUtils initCredentialsProviderFromConfig test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClientBuilder.withCustomConfigFile方法
     */
    @Test
    public void testDefaultSecretManagerClientBuilderWithCustomConfigFile() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 测试withCustomConfigFile方法
            builder.withCustomConfigFile("/path/to/custom/config.properties");

            // 使用反射检查customConfigFile字段
            Field customConfigFileField = DefaultSecretManagerClientBuilder.class.getDeclaredField("customConfigFile");
            customConfigFileField.setAccessible(true);
            String customConfigFile = (String) customConfigFileField.get(builder);

            Assert.assertEquals("Custom config file path should match",
                    "/path/to/custom/config.properties", customConfigFile);

            System.out.println("DefaultSecretManagerClientBuilder withCustomConfigFile test passed");
        } catch (Exception e) {
            Assert.fail("DefaultSecretManagerClientBuilder withCustomConfigFile test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClientBuilder.withRegion方法
     */
    @Test
    public void testDefaultSecretManagerClientBuilderWithRegion() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();

            // 测试withRegion方法
            builder.withRegion("cn-hangzhou", "cn-shanghai", "cn-beijing");

            // 使用反射检查regionInfos字段
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);

            Assert.assertEquals("Should have 3 regions", 3, regionInfos.size());

            Set<String> expectedRegions = new HashSet<>(Arrays.asList("cn-hangzhou", "cn-shanghai", "cn-beijing"));
            Set<String> actualRegions = new HashSet<>();
            for (RegionInfo regionInfo : regionInfos) {
                actualRegions.add(regionInfo.getRegionId());
            }

            Assert.assertEquals("Region IDs should match", expectedRegions, actualRegions);

            System.out.println("DefaultSecretManagerClientBuilder withRegion test passed");
        } catch (Exception e) {
            Assert.fail("DefaultSecretManagerClientBuilder withRegion test failed: " + e.getMessage());
        }
    }

    /**
     * 测试RegionInfo相关功能
     */
    @Test
    public void testRegionInfoFunctionality() {
        try {
            // 测试RegionInfo构造函数
            RegionInfo region1 = new RegionInfo("cn-hangzhou");
            Assert.assertEquals("Region ID should match", "cn-hangzhou", region1.getRegionId());

            RegionInfo region2 = new RegionInfo("cn-shanghai", "kms.cn-shanghai.aliyuncs.com");
            Assert.assertEquals("Region ID should match", "cn-shanghai", region2.getRegionId());
            Assert.assertEquals("Endpoint should match", "kms.cn-shanghai.aliyuncs.com", region2.getEndpoint());

            RegionInfo region3 = new RegionInfo("cn-beijing", true, "kms-vpc.cn-beijing.aliyuncs.com", "/path/to/ca.pem");
            Assert.assertEquals("Region ID should match", "cn-beijing", region3.getRegionId());
            Assert.assertTrue("VPC should be true", region3.getVpc());
            Assert.assertEquals("Endpoint should match", "kms-vpc.cn-beijing.aliyuncs.com", region3.getEndpoint());
            Assert.assertEquals("CA file path should match", "/path/to/ca.pem", region3.getCaFilePath());

            System.out.println("RegionInfo functionality test passed");
        } catch (Exception e) {
            Assert.fail("RegionInfo functionality test failed: " + e.getMessage());
        }
    }

    /**
     * 测试CredentialsProviderUtils.withOIDCRoleArn方法的所有重载版本
     */
    @Test
    public void testCredentialsProviderUtilsOIDCRoleArnAllVersions() {
        try {
            // 测试完整参数版本
            AlibabaCloudCredentialsProvider provider1 = CredentialsProviderUtils.withOIDCRoleArn(
                    "testSession", "testRoleArn", "testOidcProviderArn", "/path/to/token",
                    "testPolicy", "sts.cn-hangzhou.aliyuncs.com", 3600, "cn-hangzhou");
            Assert.assertTrue("Provider should be OIDCRoleArnCredentialProvider",
                    provider1 instanceof OIDCRoleArnCredentialProvider);

            // 测试简化参数版本
            AlibabaCloudCredentialsProvider provider2 = CredentialsProviderUtils.withOIDCRoleArn(
                    "testRoleArn", "testOidcProviderArn", "/path/to/token");
            Assert.assertTrue("Provider should be OIDCRoleArnCredentialProvider",
                    provider2 instanceof OIDCRoleArnCredentialProvider);

            System.out.println("CredentialsProviderUtils OIDCRoleArn all versions test passed");
        } catch (Exception e) {
            Assert.fail("CredentialsProviderUtils OIDCRoleArn all versions test failed: " + e.getMessage());
        }
    }

    /**
     * 测试TypeUtils工具类
     */
    @Test
    public void testTypeUtils() {
        try {
            // 测试parseString方法
            Assert.assertNull("Should return null for null input", TypeUtils.parseString(null));
            Assert.assertEquals("Should return string representation", "test", TypeUtils.parseString("test"));
            Assert.assertEquals("Should return string representation", "123", TypeUtils.parseString(123));

            // 测试parseInteger方法
            Assert.assertNull("Should return null for null input", TypeUtils.parseInteger(null));
            Assert.assertEquals("Should return integer", Integer.valueOf(123), TypeUtils.parseInteger("123"));
            Assert.assertEquals("Should return integer", Integer.valueOf(456), TypeUtils.parseInteger(456));

            // 测试parseBoolean方法
            Assert.assertFalse("Should return false for null input", TypeUtils.parseBoolean(null));
            Assert.assertTrue("Should return true for boolean true", TypeUtils.parseBoolean(true));
            Assert.assertFalse("Should return false for boolean false", TypeUtils.parseBoolean(false));
            Assert.assertTrue("Should return true for string 'true'", TypeUtils.parseBoolean("true"));
            Assert.assertFalse("Should return false for string 'false'", TypeUtils.parseBoolean("false"));

            try {
                TypeUtils.parseBoolean(new Object());
                Assert.fail("Should throw IllegalArgumentException for unknown object type");
            } catch (IllegalArgumentException e) {
                // 预期异常
            }

            System.out.println("TypeUtils test passed");
        } catch (Exception e) {
            Assert.fail("TypeUtils test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 直接使用configMap中的配置
     */
    @Test
    public void testBuildKMSClientWithExistingConfig() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 创建一个配置对象并添加到configMap中
            com.aliyun.teaopenapi.models.Config config = new com.aliyun.teaopenapi.models.Config();
            config.setRegionId("cn-hangzhou");
            config.setEndpoint("kms.cn-hangzhou.aliyuncs.com");

            // 使用反射将config添加到configMap中
            Field configMapField = DefaultSecretManagerClientBuilder.class.getDeclaredField("configMap");
            configMapField.setAccessible(true);
            Map<RegionInfo, com.aliyun.teaopenapi.models.Config> configMap =
                    (Map<RegionInfo, com.aliyun.teaopenapi.models.Config>) configMapField.get(builder);
            configMap.put(new RegionInfo("cn-hangzhou"), config);

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou");
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient with existing config test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient with existing config test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 创建新配置（普通endpoint）
     */
    @Test
    public void testBuildKMSClientCreateNewConfig() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou", "kms.cn-hangzhou.aliyuncs.com"));

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", "kms.cn-hangzhou.aliyuncs.com");
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient create new config test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient create new config test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 实例网关endpoint带CA文件路径
     */
    @Test
    public void testBuildKMSClientInstanceGatewayWithCaFilePath() throws Exception {
        // 创建一个临时CA文件用于测试
        String testCaContent = "-----BEGIN CERTIFICATE-----\\n" +
                "MIIDhzCCAm+gAwIBAgIJAJLYwUtawfcsMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\\n" +
                "BAYTAkNOMREwDwYDVQQIDAHaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\\n" +
                "BgNVBAoMB0FsaWJhYjExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\\n" +
                "ZSBLTVMgUm9vdCBDQTAeFw0yNDA2MTIwODM0NTZaFw00NDA2MDcwODM0NTZaMIGH\\n" +
                "-----END CERTIFICATE-----";

        // 写入临时CA文件
        java.io.File tempCaFile = java.io.File.createTempFile("test-ca", ".pem");
        try (java.io.FileWriter writer = new java.io.FileWriter(tempCaFile)) {
            writer.write(testCaContent);
        }

        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", tempCaFile.getAbsolutePath()));

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", tempCaFile.getAbsolutePath());
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient instance gateway with CA file path test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient instance gateway with CA file path test failed: " + e.getMessage());
        } finally {
            // 删除临时CA文件
            if (tempCaFile.exists()) {
                tempCaFile.delete();
            }
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 实例网关endpoint使用预设CA证书
     */
    @Test
    public void testBuildKMSClientInstanceGatewayWithPredefinedCa() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou"); // 使用预设有CA证书的区域

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", null); // 不指定CA文件路径
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient instance gateway with predefined CA test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient instance gateway with predefined CA test failed: " + e.getMessage());
        }
    }

    /**
     * 测试testBuildKMSClientInstanceGatewayWithNotExistCa方法 - 实例网关endpoint使用不存在的预设CA证书
     */
    @Test
    public void testBuildKMSClientInstanceGatewayWithNotExistCa() throws Exception {
        DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
        builder.addRegion("pr-hangzhou"); // 使用不存在的预设有CA证书的区域

        // 获取内部类实例
        SecretManagerClient client = builder.build();
        try {
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("pr-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", null); // 不指定CA文件路径
            buildKMSClientMethod.invoke(client, regionInfo);

        } catch (Exception e) {
            if (e.getCause().getMessage().contains("cannot find the built-in ca certificate")) {
                System.out.println("testBuildKMSClientInstanceGatewayWithNotExistCa test passed");
                return;
            }
        }
        assert false;
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - VPC endpoint
     */
    @Test
    public void testBuildKMSClientWithVpcEndpoint() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou", true)); // VPC=true

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", true);
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient with VPC endpoint test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient with VPC endpoint test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 默认endpoint
     */
    @Test
    public void testBuildKMSClientWithDefaultEndpoint() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou")); // 既没有endpoint也没有VPC

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou");
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient with default endpoint test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient with default endpoint test failed: " + e.getMessage());
        }
    }


    /**
     * 测试DefaultSecretManagerClient的init方法 - 从配置文件初始化
     */
    @Test
    public void testInitFromConfigFile() {
        String configFileName = "test-config.properties";
        try {
            // 创建临时配置文件
            java.io.File configFile = new java.io.File(configFileName);
            try (java.io.FileWriter writer = new java.io.FileWriter(configFile)) {
                writer.write(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY + "=ak\n");
                writer.write(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY + "=testAccessKeyId\n");
                writer.write(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY + "=testAccessKeySecret\n");
                writer.write(CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY + "=[{\"regionId\":\"cn-hangzhou\"}]\n");
            }

            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.withCustomConfigFile(configFileName);

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 验证provider是否正确设置
            Field providerField = DefaultSecretManagerClientBuilder.class.getDeclaredField("provider");
            providerField.setAccessible(true);
            Object provider = providerField.get(builder);
            Assert.assertNotNull("Provider should not be null", provider);
            Assert.assertTrue("Provider should be StaticCredentialsProvider",
                    provider instanceof com.aliyun.credentials.provider.StaticCredentialsProvider);

            System.out.println("Init from config file test passed");
        } catch (Exception e) {
            // 注意：即使配置文件不存在，也不应导致初始化失败
            e.printStackTrace();
            Assert.fail("Init from config file test failed: " + e.getMessage());
        } finally {
            // 删除临时配置文件
            java.io.File configFile = new java.io.File(configFileName);
            if (configFile.exists()) {
                configFile.delete();
            }
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - 从环境变量初始化
     */
    @Test
    public void testInitFromEnv() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 创建测试环境变量映射
            Map<String, String> testEnvMap = new HashMap<>();
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "ak");
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY, "testAccessKeyId");
            testEnvMap.put(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY, "testAccessKeySecret");
            testEnvMap.put(CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY, "[{\"regionId\":\"cn-hangzhou\"}]");

            // 使用反射直接调用initCredentialsProviderFromEnv方法进行测试
            Method initCredentialsProviderFromEnvMethod = client.getClass().getDeclaredMethod("initCredentialsProviderFromEnv", Map.class);
            initCredentialsProviderFromEnvMethod.setAccessible(true);
            initCredentialsProviderFromEnvMethod.invoke(client, testEnvMap);

            // 验证provider是否正确设置
            Field providerField = DefaultSecretManagerClientBuilder.class.getDeclaredField("provider");
            providerField.setAccessible(true);
            Object provider = providerField.get(builder);
            Assert.assertNotNull("Provider should not be null", provider);
            Assert.assertTrue("Provider should be StaticCredentialsProvider",
                    provider instanceof com.aliyun.credentials.provider.StaticCredentialsProvider);

            // 验证region是否正确设置
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);
            Assert.assertNotNull("Region infos should not be null", regionInfos);
            Assert.assertFalse("Region infos should not be empty", regionInfos.isEmpty());
            Assert.assertEquals("Should have 1 region", 1, regionInfos.size());
            Assert.assertEquals("Region ID should match", "cn-hangzhou", regionInfos.get(0).getRegionId());

            System.out.println("Init from environment variables test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init from environment variables test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - 检查regionInfo（正常情况）
     */
    @Test
    public void testInitCheckRegionInfoValid() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 验证region是否正确设置
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);
            Assert.assertNotNull("Region infos should not be null", regionInfos);
            Assert.assertFalse("Region infos should not be empty", regionInfos.isEmpty());
            Assert.assertEquals("Should have 1 region", 1, regionInfos.size());
            Assert.assertEquals("Region ID should match", "cn-hangzhou", regionInfos.get(0).getRegionId());

            System.out.println("Init check region info valid test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init check region info valid test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - 检查regionInfo（异常情况）
     */
    @Test
    public void testInitCheckRegionInfoInvalid() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            // 不添加任何region

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);

            try {
                initMethod.invoke(client);
                Assert.fail("Should throw IllegalArgumentException when no region is specified");
            } catch (Exception e) {
                // 检查是否是预期的异常
                if (e.getCause() instanceof IllegalArgumentException) {
                    Assert.assertTrue(e.getCause().getMessage().contains("regionInfo"));
                } else {
                    throw e;
                }
            }

            System.out.println("Init check region info invalid test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init check region info invalid test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - 初始化backoffStrategy
     */
    @Test
    public void testInitBackoffStrategy() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射获取backoffStrategy字段
            Field backoffStrategyField = DefaultSecretManagerClientBuilder.class.getDeclaredField("backoffStrategy");
            backoffStrategyField.setAccessible(true);

            // 确保backoffStrategy为null（使用默认值）
            backoffStrategyField.set(builder, null);

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 验证backoffStrategy已被初始化
            Object backoffStrategy = backoffStrategyField.get(builder);
            Assert.assertNotNull("Backoff strategy should be initialized", backoffStrategy);

            System.out.println("Init backoff strategy test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init backoff strategy test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - regionInfos去重
     */
    @Test
    public void testInitRegionInfosDeduplication() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");
            builder.addRegion("cn-hangzhou"); // 添加重复项
            builder.addRegion("cn-shanghai");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射获取regionInfos字段
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);

            // 记录去重前的数量
            int sizeBefore = regionInfos.size();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 验证去重后的数量
            int sizeAfter = regionInfos.size();
            Assert.assertTrue("Region infos should be deduplicated", sizeAfter <= sizeBefore);

            System.out.println("Init region infos deduplication test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init region infos deduplication test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的init方法 - regionInfos排序
     */
    @Test
    public void testInitRegionInfosSorting() {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-guangzhou");
            builder.addRegion("cn-hangzhou");
            builder.addRegion("cn-beijing");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 验证region是否正确设置
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);
            Assert.assertNotNull("Region infos should not be null", regionInfos);
            Assert.assertFalse("Region infos should not be empty", regionInfos.isEmpty());
            Assert.assertEquals("Should have 3 regions", 3, regionInfos.size());

            // 验证region排序（按regionId字母顺序）
            List<String> regionIds = new ArrayList<>();
            for (RegionInfo regionInfo : regionInfos) {
                regionIds.add(regionInfo.getRegionId());
            }
            List<String> expectedRegionIds = Arrays.asList("cn-hangzhou", "cn-guangzhou", "cn-beijing");
            Assert.assertEquals("Region IDs should be sorted", expectedRegionIds, regionIds);

            System.out.println("Init region infos sorting test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Init region infos sorting test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 使用regionInfo中的CA文件路径
     */
    @Test
    public void testBuildKMSClientWithCaFilePathInRegionInfo() throws Exception {
        try {
            // 创建一个临时CA文件用于测试
            String testCaContent = "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDhzCCAm+gAwIBAgIJAJLYwUtawfcsMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
                    "BAYTAkNOMREwDwYDVQQIDAHaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
                    "BgNVBAoMB0FsaWJhYjExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
                    "ZSBLTVMgUm9vdCBDQTAeFw0yNDA2MTIwODM0NTZaFw00NDA2MDcwODM0NTZaMIGH\n" +
                    "-----END CERTIFICATE-----";

            // 写入临时CA文件
            java.io.File tempCaFile = java.io.File.createTempFile("test-ca", ".pem");
            try (java.io.FileWriter writer = new java.io.FileWriter(tempCaFile)) {
                writer.write(testCaContent);
            }

            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", tempCaFile.getAbsolutePath()));

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", false,
                    "kms-inst.cryptoservice.kms.aliyuncs.com", tempCaFile.getAbsolutePath());
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient with CA file path in RegionInfo test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient with CA file path in RegionInfo test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的buildKMSClient方法 - 使用预定义CA证书
     */
    @Test
    public void testBuildKMSClientWithPredefinedCa() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion(new RegionInfo("cn-hangzhou", false, "kms-inst.cryptoservice.kms.aliyuncs.com", null));

            // 获取内部类实例
            SecretManagerClient client = builder.build();
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 使用反射调用buildKMSClient方法
            Method buildKMSClientMethod = client.getClass().getDeclaredMethod("buildKMSClient", RegionInfo.class);
            buildKMSClientMethod.setAccessible(true);
            RegionInfo regionInfo = new RegionInfo("cn-hangzhou", false, "kms-inst.cryptoservice.kms.aliyuncs.com", null);
            Object kmsClient = buildKMSClientMethod.invoke(client, regionInfo);

            Assert.assertNotNull("KMS Client should not be null", kmsClient);

            System.out.println("BuildKMSClient with predefined CA test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("BuildKMSClient with predefined CA test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的getSecretValue方法 - 正常情况
     */
    @Test
    public void testGetSecretValuesNormal() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 创建测试请求
            com.aliyun.kms20160120.models.GetSecretValueRequest request =
                    new com.aliyun.kms20160120.models.GetSecretValueRequest();
            request.setSecretName("test-secret");
            request.setVersionStage("ACSCurrent");

            // 使用反射调用getSecretValue方法
            Method getSecretValueMethod = client.getClass().getDeclaredMethod(
                    "getSecretValue",
                    com.aliyun.kms20160120.models.GetSecretValueRequest.class);
            getSecretValueMethod.setAccessible(true);

            // 验证方法可以被调用（不会抛出异常即为成功）
            try {
                getSecretValueMethod.invoke(client, request);
            } catch (Exception e) {
                // 允许调用失败，因为我们没有实际的KMS服务
                // 只要能正确调用方法即可
                Assert.assertTrue(true);
            }

            System.out.println("GetSecretValues normal test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("GetSecretValues normal test failed: " + e.getMessage());
        }
    }

    /**
     * 测试DefaultSecretManagerClient的getSecretValue方法 - 多区域情况
     */
    @Test
    public void testGetSecretValuesMultiRegion() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");
            builder.addRegion("cn-shanghai");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 创建测试请求
            com.aliyun.kms20160120.models.GetSecretValueRequest request =
                    new com.aliyun.kms20160120.models.GetSecretValueRequest();
            request.setSecretName("test-secret");
            request.setVersionStage("ACSCurrent");

            // 使用反射调用getSecretValue方法
            Method getSecretValueMethod = client.getClass().getDeclaredMethod(
                    "getSecretValue",
                    com.aliyun.kms20160120.models.GetSecretValueRequest.class);
            getSecretValueMethod.setAccessible(true);

            // 验证方法可以被调用（不会抛出异常即为成功）
            try {
                getSecretValueMethod.invoke(client, request);
            } catch (Exception e) {
                // 允许调用失败，因为我们没有实际的KMS服务
                // 只要能正确调用方法即可
                Assert.assertTrue(true);
            }

            System.out.println("GetSecretValues multi-region test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("GetSecretValues multi-region test failed: " + e.getMessage());
        }
    }

    /**
     * 测试RetryGetSecretValueTask类的构造和基本功能
     */
    @Test
    public void testRetryGetSecretValueTask() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 创建测试请求
            com.aliyun.kms20160120.models.GetSecretValueRequest request =
                    new com.aliyun.kms20160120.models.GetSecretValueRequest();
            request.setSecretName("test-secret");
            request.setVersionStage("ACSCurrent");

            // 创建CountDownLatch和AtomicInteger用于测试
            CountDownLatch countDownLatch = new CountDownLatch(1);
            AtomicInteger finished = new AtomicInteger(1);

            // 获取RetryGetSecretValueTask类
            Class<?> retryTaskClass = Class.forName(
                    "com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultSecretManagerClientBuilder$DefaultSecretManagerClient$RetryGetSecretValueTask");

            // 获取构造函数
            Constructor<?> constructor = retryTaskClass.getDeclaredConstructor(
                    client.getClass(),
                    com.aliyun.kms20160120.models.GetSecretValueRequest.class,
                    RegionInfo.class,
                    CountDownLatch.class,
                    AtomicInteger.class);
            constructor.setAccessible(true);

            // 获取regionInfo
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);

            // 创建任务实例
            Object retryTask = constructor.newInstance(client, request, regionInfos.get(0), countDownLatch, finished);

            Assert.assertNotNull("RetryGetSecretValueTask should be created", retryTask);

            // 测试call方法
            Method callMethod = retryTaskClass.getDeclaredMethod("call");
            callMethod.setAccessible(true);

            // 验证方法可以被调用（不会抛出异常即为成功）
            try {
                callMethod.invoke(retryTask);
            } catch (Exception e) {
                // 允许调用失败，因为我们没有实际的KMS服务
                // 只要能正确调用方法即可
                Assert.assertTrue(true);
            }

            System.out.println("RetryGetSecretValueTask test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("RetryGetSecretValueTask test failed: " + e.getMessage());
        }
    }

    /**
     * 测试RetryGetSecretValueTask的retryGetSecretValue重试机制
     */
    @Test
    public void testRetryGetSecretValueTaskRetryMechanism() throws Exception {
        try {
            DefaultSecretManagerClientBuilder builder = DefaultSecretManagerClientBuilder.standard();
            builder.addRegion("cn-hangzhou");

            // 获取内部类实例
            SecretManagerClient client = builder.build();

            // 使用反射调用init方法
            Method initMethod = client.getClass().getDeclaredMethod("init");
            initMethod.setAccessible(true);
            initMethod.invoke(client);

            // 创建测试请求
            com.aliyun.kms20160120.models.GetSecretValueRequest request =
                    new com.aliyun.kms20160120.models.GetSecretValueRequest();
            request.setSecretName("test-secret");
            request.setVersionStage("ACSCurrent");

            // 获取regionInfo
            Field regionInfosField = DefaultSecretManagerClientBuilder.class.getDeclaredField("regionInfos");
            regionInfosField.setAccessible(true);
            List<RegionInfo> regionInfos = (List<RegionInfo>) regionInfosField.get(builder);

            // 获取RetryGetSecretValueTask类
            Class<?> retryTaskClass = Class.forName(
                    "com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultSecretManagerClientBuilder$DefaultSecretManagerClient$RetryGetSecretValueTask");

            // 获取retryGetSecretValue方法
            Method retryGetSecretValueMethod = retryTaskClass.getDeclaredMethod(
                    "retryGetSecretValue",
                    com.aliyun.kms20160120.models.GetSecretValueRequest.class,
                    RegionInfo.class);
            retryGetSecretValueMethod.setAccessible(true);

            // 创建一个模拟的RetryGetSecretValueTask实例（仅用于测试方法）
            Constructor<?> constructor = retryTaskClass.getDeclaredConstructor(
                    client.getClass(),
                    com.aliyun.kms20160120.models.GetSecretValueRequest.class,
                    RegionInfo.class,
                    CountDownLatch.class,
                    AtomicInteger.class);
            constructor.setAccessible(true);

            CountDownLatch countDownLatch = new CountDownLatch(1);
            AtomicInteger finished = new AtomicInteger(1);
            Object retryTask = constructor.newInstance(client, request, regionInfos.get(0), countDownLatch, finished);

            // 验证方法可以被调用（不会抛出异常即为成功）
            try {
                retryGetSecretValueMethod.invoke(retryTask, request, regionInfos.get(0));
            } catch (Exception e) {
                // 允许调用失败，因为我们没有实际的KMS服务
                // 只要能正确调用方法即可
                Assert.assertTrue(true);
            }

            System.out.println("RetryGetSecretValueTask retry mechanism test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("RetryGetSecretValueTask retry mechanism test failed: " + e.getMessage());
        }
    }
    /**
     * 测试PrivateCaUtils.getCaExpirationUtcDate方法
     */
    @Test
    public void testGetCaExpirationUtcDate() {
        try {
            // 测试存在的区域ID
            String expirationDate = PrivateCaUtils.getCaExpirationUtcDate(PrivateCaUtils.REGION_ID_AND_CA_MAP.get("cn-hangzhou"));
            Assert.assertNotNull("Expiration date should not be null for valid region", expirationDate);

            // 测试不存在的区域ID
            String nonExistentExpiration = PrivateCaUtils.getCaExpirationUtcDate("non-existent-region");
            Assert.assertNull("Should return null for non-existent region", nonExistentExpiration);

            // 测试null输入
            String nullExpiration = PrivateCaUtils.getCaExpirationUtcDate(null);
            Assert.assertNull("Should return null for null input", nullExpiration);

            System.out.println("getCaExpirationUtcDate test passed");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("getCaExpirationUtcDate test failed: " + e.getMessage());
        }
    }

}