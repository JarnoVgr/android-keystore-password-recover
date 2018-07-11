public class AndroidKeystoreBrute {
    static final int BRUTE = 1;
    static final int WORD = 2;
    static final int SWORD = 3;
    private static final String VERSION = "1.08";
    static boolean saveNewKeystore = false;
    static boolean onlyLowerCase = false;
    static boolean disableSpecialChars = false;
    static boolean permutations = false;
    static int minLength = 0;
    static int minPieces = 1;
    static int maxPieces = 64;
    static String firstchars = null;

    public static void main(String[] args) throws Exception {
        String start = "A";
        int method = 0;

        String keystore = "";
        String dict = "";

        if (args.length == 0) {
            printHelp();
            return;
        }

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h":
                    printHelp();
                    return;
                case "-m":
                    i++;
                    method = Integer.parseInt(args[i]);
                    break;
                case "-k":
                    i++;
                    keystore = args[i];
                    break;
                case "-d":
                    i++;
                    dict = args[i];
                    break;
                case "-p":
                    permutations = true;
                    break;
                case "-w":
                    saveNewKeystore = true;
                    break;
                case "-start":
                    i++;
                    start = args[i];
                    break;
                case "-l":
                    i++;
                    minLength = Integer.parseInt(args[i]);
                    break;
                case "-onlylower":
                    onlyLowerCase = true;
                    break;
                case "-nospecials":
                    disableSpecialChars = true;
                    break;
                case "-firstchars":
                    i++;
                    firstchars = args[i];
                    break;
                case "-pieces":
                    i++;
                    minPieces = Integer.parseInt(args[i]);
                    i++;
                    maxPieces = Integer.parseInt(args[i]);
                    break;
                default:
                    System.out.println("Ignoring unknown argument: " + args[i]);
                    break;
            }
        }

        if (method == BRUTE) {
            if (onlyLowerCase && start.equals("A"))
                start = "a";

            BrutePasswd.go(keystore, start);
        } else if (method == WORD)
            WordlistPasswd.doit(keystore, dict);
        else if (method == SWORD)
            SmartWordlistPasswd.doit(keystore, dict);
        else
            printHelp();
    }

    static void quit() {
        System.exit(0);
    }

    private static void printHelp() {
        System.out.println("AndroidKeystorePasswordRecoveryTool by M@xiking");
        System.out.println("v1.06 updated by rafaelwbr; v1.07 updated by ravensbane; v1.08 updated by JarnoVgr");
        System.out.println("Version " + VERSION + "\r\n");
        System.out.println("There are 3 Methods to recover the key for your Keystore:\r\n");
        System.out.println("1: simply bruteforce - good luck");
        System.out.println("2: dictionary attack - your password has to be in the dictionary");
        System.out.println("3: smart dictionary attack - you specify a dictionary with regular pieces you use in your passwords. Numbers are automaticly added and first letter will tested uppercase and lowercase. This method can resume when interrupted as long as you specify the same arguments.\r\n");
        System.out.println("args:");
        System.out.println("-m <1..3> Method");
        System.out.println("-k <path> path to your keystore");
        System.out.println("-d <path> dictionary (for method 2 and 3)");
        System.out.println("-l <min> sets min password length in characters (for method 3)");
        System.out.println("-start <String> sets start String of the word (for method 1)");
        System.out.println("-firstchars <String> specify first characters of the password (for method 3)");
        System.out.println("-pieces <min> <max> specify the min and max number of pieces to use when building passwords (for method 3)\r\n");

        System.out.println("-nospecials to not try special characters in password (makes cracking faster for simple passwords)");
        System.out.println("-onlylower for only lowercase letters");
        System.out.println("-w saves the certificate in a new Keystore with same password as key");
        System.out.println("-p use common replacements like '@' for 'a'(for method 3) WARNING: This is very slow. Do not use on dictionaries with more than 250 entries.\r\n");
        System.out.println("-h prints this helpscreen\r\n");

        long maxBytes = Runtime.getRuntime().maxMemory();
        System.out.println("Max memory: " + maxBytes / 1024L / 1024L + "M\r\n");
    }
}
