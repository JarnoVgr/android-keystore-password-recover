import java.io.FileInputStream;
import java.io.InputStream;

public class BrutePasswd extends BasePasswd {
    static volatile boolean found = false;

    static int testedPwds = 0;

    static char[] currPass;

    private static char[] alphabet = {};

    private static char[] alphabetUpper = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
            'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
            'W', 'X', 'Y', 'Z'
    };

    private static char[] alphabetLower = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g',
            'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
            's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    };

    private static char[] numeric = {
            '0', '1', '2',
            '3', '4', '5', '6', '7', '8', '9'
    };

    private static char[] specialChars = {
            '!', '"', '@', '#', '$', '%', '&', '/', '{', '>',
            '}', '(', ')', '[', ']', '=', '?', '+', '`', '|',
            '^', '~', '*', '-', '_', '.', ':', ',', ';', '<',
            '\'', '\\',
    };

    private BrutePasswd() throws Exception {
        FileInputStream in = new FileInputStream(keystoreFileName);
        engineLoad(in, currPass);
    }

    static public void go(String keystore) throws Exception {
        go(keystore, AndroidKeystoreBrute.enableUpperCase ? "A" : "a");
    }

    private static void setupAlphabet() {
        String alphabetStr = "";
        if (AndroidKeystoreBrute.enableUpperCase)
            alphabetStr = alphabetStr + String.valueOf(alphabetUpper);
        if (AndroidKeystoreBrute.enableLowerCase)
            alphabetStr = alphabetStr + String.valueOf(alphabetLower);
        if (AndroidKeystoreBrute.enableNumeric)
            alphabetStr = alphabetStr + String.valueOf(numeric);
        if (AndroidKeystoreBrute.enableSpecialChars)
            alphabetStr = alphabetStr + String.valueOf(specialChars);

        alphabet = alphabetStr.toCharArray();
    }

    static void go(String keystore, String start) throws Exception {
        go();
        setupAlphabet();

        char[] pass;
        pass = start.toCharArray();

        InputStream in = new FileInputStream(keystore);
        currPass = pass;

        numberOfThreads = Runtime.getRuntime().availableProcessors() * 2;

        loadKeystore(in, pass);

        try {
            keystoreFileName = keystore;

            for (int i = 0; i < numberOfThreads; i++) {
                Thread t = new BrutePasswd();
                t.start();
            }

            new BruteBenchmark().start();

            System.out.println("Fire up " + numberOfThreads + " Threads\r\n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private synchronized static char[] nextWord(char[] str) {
        testedPwds++;
        currPass = nextWord(currPass, currPass.length - 1);
        if (str.length != currPass.length)
            str = new char[currPass.length];

        System.arraycopy(currPass, 0, str, 0, currPass.length);
        return str;
    }

    private static char[] nextWord(char[] word, int stelle) {
        if (word[stelle] == alphabet[alphabet.length - 1]) {
            word[stelle] = alphabet[0];
            if (stelle > 0) {
                return nextWord(word, stelle - 1);
            } else {
                char[] longerWord = new char[word.length + 1];
                longerWord[0] = alphabet[0];
                System.arraycopy(word, 0, longerWord, 1, word.length);
                return longerWord;
            }
        } else {
            for (int i = 0; i < alphabet.length; i++) {
                if (word[stelle] == alphabet[i]) {
                    word[stelle] = alphabet[i + 1];
                    break;
                }
            }
            return word;
        }
    }

    public void run() {
        char[] str = new char[1];

        while (!found) {
            str = nextWord(str);

            if (keyIsRight(str)) {
                String passwd = String.copyValueOf(str);
                found = true;

                foundPassword(passwd);
                AndroidKeystoreBrute.quit();
            }
        }
    }
}
