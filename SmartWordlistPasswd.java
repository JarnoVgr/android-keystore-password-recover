import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.concurrent.LinkedTransferQueue;

public class SmartWordlistPasswd extends BasePasswd {
    private static final int MAGIC = 0xFEEDFEED;
    private static final int PRIVATE_KEY = 1;
    private static final int TRUSTED_CERT = 2;
    static String alias = "";
    static JKS j;
    static String keystoreFileName;
    static String dictFileName;
    static boolean found = false;
    static boolean allPwdsTested = false;
    static int testedPwds = 0;
    // --------------------------------JKS Methods------------------------------------------
    // ravensbane: these have been modified to be thread-safe
    static volatile byte[] encr;
    static volatile byte[] check;

    public static void doit(String keystore, String dict) throws Exception {
        String pass = "a";

        InputStream in = new FileInputStream(keystore);

        try {
            j = new JKS();
            j.engineLoad(in, pass.toCharArray());
            System.out.println("\r\nNumber of keys in keystore: " + j.engineSize());

            @SuppressWarnings("rawtypes")
            Enumeration e = j.engineAliases();

            while (e.hasMoreElements()) {
                String a = (String) e.nextElement();
                System.out.println("Found alias: " + a);
                System.out.println("Creation Date: " + j.engineGetCreationDate(a));
                alias = a;
            }

            in.close();

            // call our version of these jks methods to perform setup (won't work without this)
            in = new FileInputStream(keystore);
            SmartWordlistPasswd.engineLoad(in, pass.toCharArray());
            in.close();

            keystoreFileName = keystore;
            dictFileName = dict;

            System.out.println("\r\nStarting smart wordlist attack on key!!");
            if (AndroidKeystoreBrute.permutations)
                System.out.println("Using common replacements");
            else if (!AndroidKeystoreBrute.onlyLowerCase)
                System.out.println("Trying variations with first letter capitalized\r\n");

            int numberOfThreads = Runtime.getRuntime().availableProcessors();
            System.out.println("Firing up " + numberOfThreads + " threads\r\n");

            // we'll use this queue to hold password combinations we're waiting to test
            LinkedTransferQueue<String> queue = new LinkedTransferQueue<String>();

            // start producer thread (adds password combinations to the queue)
            Thread producer = new Thread(new SmartWordlistProducer(queue, dict));
            producer.start();

            // start consumer threads (removes password combinations from the queue and tests them)
            for (int i = 0; i < numberOfThreads; i++) {
                Thread consumer = new Thread(new SmartWordlistConsumer(queue));
                consumer.start();
            }

            // start benchmark and auto-save threads
            new SmartWordlistBenchmark().start();
            new SmartWordlistResume().start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void complete(String passwd) {
        if (found)
            foundPassword(passwd);
        else
            System.out.println("No matching key combination in wordlist; try another wordlist.");

        AndroidKeystoreBrute.quit();
    }
}
