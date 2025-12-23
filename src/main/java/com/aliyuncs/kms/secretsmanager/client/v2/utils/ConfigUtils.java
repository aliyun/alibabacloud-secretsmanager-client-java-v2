package com.aliyuncs.kms.secretsmanager.client.v2.utils;


import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class ConfigUtils {

    private ConfigUtils() {
        // do nothing
    }

    /**
     * 加载配置文件
     *
     * @param configName 配置文件名称
     * @return 配置属性对象
     */
    public static Properties loadConfig(String configName) {
        File file = getFileByPath(configName);
        Properties properties = new Properties();
        if (file == null) {
            try (InputStream in = ConfigUtils.class.getClassLoader().getResourceAsStream(configName)) {
                if (in == null) {
                    return null;
                }
                properties.load(in);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            try (InputStream in = Files.newInputStream(file.toPath())) {
                properties.load(in);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return properties;
    }

    /**
     * 根据文件路径获取文件对象
     *
     * @param filePath 文件路径
     * @return 文件对象，如果文件不存在则返回null
     */
    public static File getFileByPath(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            URL resource = ConfigUtils.class.getClassLoader().getResource("");
            String path = "";
            if (resource != null) {
                path = resource.getPath();
            }
            if (!(file = new File(path + filePath)).exists()) {
                path = Paths.get(filePath).toAbsolutePath().toString();
                if (!(file = new File(path)).exists()) {
                    return null;
                }
            }
        }
        return file;
    }

    /**
     * 读取文件内容
     *
     * @param filePath 文件路径
     * @return 文件内容字符串
     */
    public static String readFileContent(String filePath) {
        File file = getFileByPath(filePath);
        if (file == null || !file.exists()) {
            try (InputStream in = ConfigUtils.class.getClassLoader().getResourceAsStream(filePath);
                 BufferedReader reader = in == null ? null : new BufferedReader(new InputStreamReader(in))
            ) {
                if (in == null) {
                    throw new FileNotFoundException(String.format("file not found: %s", filePath));
                }
                return readContent(reader);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                return readContent(reader);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

    }

    /**
     * 从BufferedReader中读取内容
     *
     * @param reader BufferedReader对象
     * @return 读取的内容字符串
     * @throws IOException IO异常
     */
    private static String readContent(BufferedReader reader) throws IOException {
        if (reader == null) {
            return null;
        }
        StringBuilder content = new StringBuilder();
        String line;
        boolean firstLine = true;
        while ((line = reader.readLine()) != null) {
            if (!firstLine) {
                content.append(System.lineSeparator());
            }
            content.append(line);
            firstLine = false;
        }
        return content.toString();
    }
}
