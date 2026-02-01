// Demo1.java
// 专门用于测试 SpotBugs 的漏洞示例文件

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Random;

/**
 * 这个类包含多种常见漏洞，用于测试 SpotBugs 的检测能力
 */
public class Demo1 {

    // 漏洞1: 硬编码密码 - SpotBugs 规则: HARD_CODE_PASSWORD
    private String password = "mySecretPassword123";

    // 漏洞2: 空指针解引用 - SpotBugs 规则: NP_NULL_ON_SOME_PATH
    public void potentialNPE(String input) {
        if (input.equals("test")) { // 可能抛出 NPE
            System.out.println("Match found");
        }
    }

    // 漏洞3: 资源未关闭 - SpotBugs 规则: OBL_UNSATISFIED_OBLIGATION
    public void readFileWithoutClosing() {
        try {
            FileInputStream fis = new FileInputStream("test.txt");
            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            String line = br.readLine();
            System.out.println(line);
            // 忘记关闭流 - 资源泄漏
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 漏洞4: 不安全的随机数生成器 - SpotBugs 规则: PREDICTABLE_RANDOM
    public int generateInsecureRandom() {
        Random random = new Random(); // 不使用安全随机数
        return random.nextInt();
    }

    // 漏洞5: 使用弱哈希算法 (MD5) - SpotBugs 规则: WEAK_MESSAGE_DIGEST
    public String insecureHash(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // 不安全的 MD5
            byte[] hash = md.digest(data.getBytes());
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

    // 漏洞6: 可能的 SQL 注入 - SpotBugs 规则: SQL_INJECTION
    public void potentialSQLInjection(String userInput) {
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'"; // 字符串拼接
        // 执行查询...
    }

    // 漏洞7: 不安全的反序列化 - SpotBugs 规则: SERIALIZABLE_HAS_DEFENSIVE_READOBJECT
    public void deserializeData(byte[] data) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject(); // 不安全的反序列化
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 漏洞8: 错误的 equals 比较 - SpotBugs 规则: ES_COMPARING_STRINGS_WITH_EQ
    public boolean wrongStringComparison(String str1, String str2) {
        return str1 == str2; // 应该使用 equals()
    }

    // 漏洞9: 未使用的变量 - SpotBugs 规则: URF_UNREAD_FIELD
    private String unusedField = "This field is never used";

    // 漏洞10: 可疑的代码模式 - SpotBugs 规则: DLS_DEAD_LOCAL_STORE
    public void deadLocalStore() {
        int x = 10; // 赋值后未使用
        x = 20;
        System.out.println("Value: " + x);
    }

    // 漏洞11: 线程安全问题 - SpotBugs 规则: IS2_INCONSISTENT_SYNC
    private int counter = 0;

    public void incrementNotThreadSafe() {
        counter++; // 非原子操作，线程不安全
    }

    // 漏洞12: 数学运算问题 - SpotBugs 规则: INT_BAD_REM_BY_1
    public int badMathOperation(int a, int b) {
        return a % 1; // 总是返回 0
    }

    // 漏洞13: 日期处理问题 - SpotBugs 规则: DM_USELESS_THREAD
    public void uselessThread() {
        Thread t = new Thread(() -> {
            System.out.println("Running");
        });
        t.run(); // 应该用 start() 而不是 run()
    }

    // 主方法用于测试
    public static void main(String[] args) {
        Demo1 demo = new Demo1();

        // 测试各种漏洞方法
        demo.potentialNPE(null); // 可能触发 NPE
        demo.readFileWithoutClosing();
        demo.generateInsecureRandom();
        demo.insecureHash("test");
        demo.potentialSQLInjection("admin' OR '1'='1"); // SQL 注入示例
        demo.wrongStringComparison("hello", "hello");
        demo.deadLocalStore();
        demo.incrementNotThreadSafe();
        demo.badMathOperation(10, 5);
        demo.uselessThread();
    }
}
