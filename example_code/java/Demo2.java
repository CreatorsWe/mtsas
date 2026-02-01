// Demo2.java
// 包含多种常见安全漏洞的测试代码

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Random;

/**
 * 这个类包含多种常见 Java 安全漏洞，用于测试静态分析工具
 */
public class Demo2 {

    // 漏洞1: 硬编码密码 - 静态分析工具应该检测到
    private static final String DB_PASSWORD = "mySecretPassword123";
    private static final String API_KEY = "sk_live_1234567890abcdef";

    // 漏洞2: 可能的空指针异常
    public void potentialNullPointerException(String input) {
        if (input.equals("test")) { // 可能抛出 NullPointerException
            System.out.println("Input matches test");
        }
    }

    // 漏洞3: SQL 注入漏洞
    public void sqlInjectionVulnerable(String userInput) {
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        // 执行查询...
        System.out.println("Query: " + query);
    }

    // 漏洞4: 命令注入漏洞
    public void commandInjectionVulnerable(String filename) {
        try {
            Runtime.getRuntime().exec("rm -f " + filename); // 命令注入风险
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 漏洞5: 路径遍历漏洞
    public void pathTraversalVulnerable(String userInput) {
        File file = new File("/var/www/html/" + userInput);
        // 文件操作...
        System.out.println("File path: " + file.getAbsolutePath());
    }

    // 漏洞6: 不安全的反序列化
    public void insecureDeserialization(byte[] data) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject(); // 不安全的反序列化
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 漏洞7: 使用弱哈希算法 (MD5)
    public String weakHashing(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // 不安全的 MD5
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 漏洞8: 不安全的随机数生成器
    public int insecureRandom() {
        Random random = new Random(); // 不安全的随机数生成
        return random.nextInt();
    }

    // 漏洞9: 资源未正确关闭
    public void resourceLeak(String filename) {
        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            String line = reader.readLine();
            System.out.println(line);
            // 忘记关闭资源
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 漏洞10: 不安全的文件权限
    public void insecureFilePermissions() {
        File file = new File("/tmp/sensitive.txt");
        file.setWritable(true, false); // 全局可写
    }

    // 漏洞11: XSS 漏洞（在 Web 环境中）
    public void potentialXSS(String userInput) {
        String html = "<div>" + userInput + "</div>"; // 潜在的 XSS
        System.out.println(html);
    }

    // 漏洞12: 不安全的 SSL/TLS 配置（模拟）
    public void insecureSSL() {
        // 模拟不安全的 SSL 配置
        System.setProperty("https.protocols", "SSLv3"); // 不安全的协议
    }

    // 漏洞13: 信息泄露
    public void informationDisclosure(Exception e) {
        e.printStackTrace(); // 可能泄露敏感信息
        System.out.println("Error: " + e.getMessage()); // 可能泄露堆栈跟踪
    }

    // 漏洞14: 不安全的加密使用
    public void insecureCrypto() {
        // 使用弱加密算法（示例）
        System.out.println("Using weak crypto algorithm");
    }

    // 漏洞15: 竞态条件
    private int counter = 0;

    public void raceCondition() {
        // 非线程安全的计数器递增
        counter++;
    }

    // 主方法用于演示
    public static void main(String[] args) {
        Demo2 demo = new Demo2();

        // 测试各种漏洞
        demo.potentialNullPointerException(null);
        demo.sqlInjectionVulnerable("admin' OR '1'='1");
        demo.commandInjectionVulnerable("important_file; rm -rf /");
        demo.pathTraversalVulnerable("../../../etc/passwd");
        demo.weakHashing("password123");
        demo.insecureRandom();
        demo.resourceLeak("test.txt");

        // 显示硬编码的敏感信息（不应该在生产环境中这样做）
        System.out.println("DB Password: " + DB_PASSWORD);
        System.out.println("API Key: " + API_KEY);
    }
}

// 不安全的序列化类示例
class InsecureSerializable implements Serializable {
    private String data;

    // 不安全的 readObject 方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 可能执行恶意代码
    }
}
