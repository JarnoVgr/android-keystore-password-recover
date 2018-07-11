import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

class BasePasswd extends Thread {
    private static final int MAGIC = 0xFEEDFEED;
    private static final int PRIVATE_KEY = 1;
    private static final int TRUSTED_CERT = 2;
    private static String alias = "";
    private static JKS j;
    static String keystoreFileName;
    static int numberOfThreads = 8;
    private static MessageDigest sha;
    private static byte[] key;
    private static byte[] keystream;
    private static byte[] encr;
    private static byte[] check;
    private static byte[] encoded;
    static private long initTime;

    BasePasswd() {
    }

    static void go() {
        initTime = System.currentTimeMillis();
    }

    static void loadKeystore(InputStream in, char[] pass) {
        j = new JKS();
        try {
            j.engineLoad(in, pass);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("\r\nNumber of keys in keystore: " + j.engineSize());

        //@SuppressWarnings("rawtypes")
        Enumeration e = j.engineAliases();

        while (e.hasMoreElements()) {
            String a = (String) e.nextElement();
            System.out.println("Found alias: " + a);
            System.out.println("Creation Date: " + j.engineGetCreationDate(a));
            alias = a;
        }

        try {
            in.close();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    static boolean decryptKey(byte[] passwd) {
        try {
            System.arraycopy(encr, 0, keystream, 0, 20);

            int count = 0;

            while (count < key.length) {
                sha.reset();
                sha.update(passwd);
                sha.update(keystream);
                sha.digest(keystream, 0, keystream.length);

                for (int i = 0; (i < keystream.length) && (count < key.length); i++) {
                    key[count] = (byte) (keystream[i] ^ encr[count + 20]);
                    count++;
                }
            }

            sha.reset();
            sha.update(passwd);
            sha.update(key);

            return MessageDigest.isEqual(check, sha.digest());
        } catch (Exception x) {
            return false;
        }
    }

    static void engineLoad(InputStream in, char[] passwd)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(charsToBytes(passwd));
        md.update("Mighty Aphrodite".getBytes("UTF-8")); // HAR HAR

        DataInputStream din = new DataInputStream(new DigestInputStream(in, md));

        if (din.readInt() != MAGIC) {
            throw new IOException("not a JavaKeyStore");
        }

        din.readInt(); // version no.

        final int n = din.readInt();

        if (n < 0) {
            throw new IOException("negative entry count");
        }

        int type = din.readInt();
        alias = din.readUTF();
        din.readLong(); // Skip Date

        switch (type) {
            case PRIVATE_KEY:

                int len = din.readInt();
                encoded = new byte[len];
                din.read(encoded);

                // privateKeys.put(alias, encoded);
                int count = din.readInt();
                Certificate[] chain = new Certificate[count];

                for (int j = 0; j < count; j++)
                    chain[j] = JKS.readCert(din);

                // certChains.put(alias, chain);
                break;

            case TRUSTED_CERT:

                // trustedCerts.put(alias, readCert(din));
                break;

            default:
                throw new IOException("malformed key store");
        }

        encr = new EncryptedPrivateKeyInfo(encoded).getEncryptedData();
        keystream = new byte[20];
        System.arraycopy(encr, 0, keystream, 0, 20);
        check = new byte[20];
        System.arraycopy(encr, encr.length - 20, check, 0, 20);
        key = new byte[encr.length - 40];
        sha = MessageDigest.getInstance("SHA1");

        byte[] hash = new byte[20];
        din.read(hash);

        if (MessageDigest.isEqual(hash, md.digest())) {
            throw new IOException("signature not verified");
        }
    }

    static boolean keyIsRight(char[] password) {
        try {
            return decryptKey(charsToBytes(password));
        } catch (Exception x) {
            return false;
        }
    }

    private static byte[] charsToBytes(char[] passwd) {
        byte[] buf = new byte[passwd.length * 2];

        for (int i = 0, j = 0; i < passwd.length; i++) {
            buf[j++] = (byte) (passwd[i] >>> 8);
            buf[j++] = (byte) passwd[i];
        }

        return buf;
    }

    static void foundPassword(String passwd) {
        // We are lucky
        System.out.println("Got Password in " + ((System.currentTimeMillis() - initTime)) / 1000 + " seconds");
        System.out.println("Password is: " + passwd + " for alias " + alias);

        saveNewKeystore(passwd);
    }

    private static void saveNewKeystore(String passwd) {
        try {
            if (AndroidKeystoreBrute.saveNewKeystore) {
                j.engineStore(new FileOutputStream(keystoreFileName + "_recovered"), passwd.toCharArray());
                System.out.println("Saved new keystore to: " + keystoreFileName + "_recovered");
            } // end of if
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
