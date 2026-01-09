package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.tea.TeaException;
import org.slf4j.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommonLogger implements Closeable {

    private static final Map<String, CommonLogger> commonLoggerMap = new HashMap<>();
    /**
     * 有效模块
     */
    private static final List<String> allowModes = new ArrayList<String>() {{
        add(CacheClientConstant.MODE_NAME);
    }};
    private final Logger logger;
    private final String modeName;

    private CommonLogger(String modeName, Logger logger) {
        this.logger = logger;
        this.modeName = modeName;
    }

    /**
     * 注册logger
     *
     * @param modeName
     * @param logger
     */
    public static void registerLogger(String modeName, Logger logger) {
        if (!allowModes.contains(modeName)) {
            throw new IllegalArgumentException(String.format("the modeName [%s] is invalid", modeName));
        }
        commonLoggerMap.put(modeName, new CommonLogger(modeName, logger));
    }

    /**
     * 获取commonLogger
     *
     * @param modeName
     * @return
     */
    public static CommonLogger getCommonLogger(String modeName) {
        if (!commonLoggerMap.containsKey(modeName)) {
            throw new IllegalArgumentException(String.format("the modeName [%s] need register", modeName));
        }
        return commonLoggerMap.get(modeName);
    }

    /**
     * 是否注册commonLogger
     *
     * @param modeName
     * @return
     */
    public static boolean isRegistered(String modeName) {
        return commonLoggerMap.containsKey(modeName);
    }


    public void tracef(String format, Object... parameters) {
        logger.trace(parseExceptionErrorMsg(format, parameters), parameters);
    }

    public void infof(String format, Object... parameters) {
        logger.info(parseExceptionErrorMsg(format, parameters), parameters);
    }

    public void debugf(String format, Object... parameters) {
        logger.debug(parseExceptionErrorMsg(format, parameters), parameters);
    }

    public void warnf(String format, Object... parameters) {
        logger.warn(parseExceptionErrorMsg(format, parameters), parameters);
    }

    public void errorf(String format, Object... parameters) {
        logger.error(parseExceptionErrorMsg(format, parameters), parameters);
    }

    public String parseExceptionErrorMsg(String format, Object[] parameters) {
        if (parameters != null && parameters.length > 0) {
            Object parameter = parameters[parameters.length - 1];
            if (parameter instanceof TeaException) {
                TeaException ce = (TeaException) parameter;
                format = format + String.format("\tmodeName:%s\terrorCode:%s\terrMsg:%s\terrorDescription:%s\trequestId:%s", modeName, ce.getCode(), ce.getMessage(), ce.getDescription(), ce.getData() != null ? ce.getData().get("RequestId") : null);
            } else if (parameter instanceof Throwable) {
                Throwable e = (Throwable) parameter;
                if (e.getCause() != null && e.getCause() instanceof TeaException) {
                    TeaException ce = (TeaException) e.getCause();
                    format = format + String.format("\tmodeName:%s\terrorCode:%s\terrMsg:%s\terrorDescription:%s\trequestId:%s", modeName, ce.getCode(), ce.getMessage(), ce.getDescription(), ce.getData() != null ? ce.getData().get("RequestId") : null);
                }
            }
        }
        return format;
    }

    public void close() throws IOException {

    }
}
