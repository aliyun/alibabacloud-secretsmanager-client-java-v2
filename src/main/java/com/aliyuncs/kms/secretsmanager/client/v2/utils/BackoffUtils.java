package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.tea.TeaException;
import com.aliyun.tea.TeaUnretryableException;
import com.aliyun.tea.utils.StringUtils;

import java.net.SocketTimeoutException;

public class BackoffUtils {

    /**
     * KMS限流返回错误码
     */
    private final static String REJECTED_THROTTLING = "Rejected.Throttling";
    /**
     * KMS服务不可用返回错误码
     */
    private final static String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";
    /**
     * KMS服务内部错误返回错误码
     */
    private final static String INTERNAL_FAILURE = "InternalFailure";

    private BackoffUtils() {
        // do noting
    }

    /**
     * 根据Client异常判断是否进行规避重试
     *
     * @param e 指定Client异常
     * @return
     */
    public static boolean judgeNeedBackoff(TeaException e) {
        return REJECTED_THROTTLING.equals(e.getCode()) || SERVICE_UNAVAILABLE_TEMPORARY.equals(e.getCode()) || INTERNAL_FAILURE.equals(e.getCode());
    }

    /**
     * 根据Client异常判断是否进行容灾重试
     *
     * @param e 指定Client异常
     * @return
     */
    public static boolean judgeNeedRecoveryException(Exception e) {
        if (e instanceof TeaUnretryableException) {
            return !StringUtils.isEmpty(e.getMessage()) && (e.getCause() instanceof SocketTimeoutException || e.getMessage().contains(CacheClientConstant.SDK_READ_TIMEOUT));
        } else if (e instanceof TeaException) {
            return ((TeaException) e).getCode().equals(CacheClientConstant.SDK_READ_TIMEOUT) ||judgeNeedBackoff((TeaException) e);
        }
        return false;
    }
}
