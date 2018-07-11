import java.io.*;
import java.util.Enumeration;

public class WordlistPasswd extends BasePasswd {
    static String alias = "";
    static JKS j;
    static boolean found = false;
    static String currentPass = "";
    static String passwd = null;
    static int testedPwds = 0;

    public static void doit(String keystore, String wordlist) throws Exception {

        InputStream in = new FileInputStream(keystore);
        char[] pass = new char[1];

        try {
            j = new JKS();
            j.engineLoad(in, pass);
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

            BufferedReader file = new BufferedReader(new InputStreamReader(new FileInputStream(wordlist)));
            System.out.println("\r\nStart dictionary attack on key!!\r\n");

            new WordlistBenchmark().start();
            in = new FileInputStream(keystore);
            engineLoad(in, pass);

            while ((currentPass != null) & (!found)) {
                currentPass = file.readLine();
                try {
                    testedPwds++;
                    // if this throws an Exception; pwd is false
                    if (keyIsRight(currentPass.toCharArray())) {
                        // if no Exception was thrown we have the password
                        found = true;
                        passwd = currentPass;
                        break;
                    }

                } catch (Exception ex) {
                    // passwd was wrong
                }
            }
            file.close();

            if (found) {
                foundPassword(passwd);
            } else {
                System.out.println("No matching key in wordlist; try an other wordlist!!");
            }

            AndroidKeystoreBrute.quit();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
