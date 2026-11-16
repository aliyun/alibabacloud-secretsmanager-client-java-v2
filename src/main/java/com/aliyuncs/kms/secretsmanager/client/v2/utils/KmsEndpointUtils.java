package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.tea.utils.StringUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;

/**
 * KMS endpoint 工具类
 */
public class KmsEndpointUtils {

    private KmsEndpointUtils() {
        // do nothing
    }

    public static String getVPCEndpoint(String regionId) {
        return "kms-vpc." + regionId + ".aliyuncs.com";
    }

    public static String getEndPoint(String regionId) {
        return "kms." + regionId + ".aliyuncs.com";
    }

    /**
     * 解析 endpoint
     *
     * @param regionInfo 区域信息
     * @return endpoint
     */
    public static String resolveEndpoint(RegionInfo regionInfo) {
        if (!StringUtils.isEmpty(regionInfo.getEndpoint())) {
            return regionInfo.getEndpoint();
        } else if (regionInfo.getVpc()) {
            return getVPCEndpoint(regionInfo.getRegionId());
        }
        return getEndPoint(regionInfo.getRegionId());
    }
}
