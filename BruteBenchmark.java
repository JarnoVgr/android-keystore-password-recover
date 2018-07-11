public class BruteBenchmark extends Thread {
    public void run() {
        long lastCall = System.currentTimeMillis();
        int lastCount = 0;
        while (!BrutePasswd.found) {
            //Check call time
            long timeDiff = System.currentTimeMillis() - lastCall;
            if (timeDiff >= 3000) {
                //Update call time
                lastCall = System.currentTimeMillis();

                //
                int testedPwds = BrutePasswd.testedPwds - lastCount;
                lastCount = BrutePasswd.testedPwds;

                if (testedPwds > 0)
                    testedPwds = Math.round(((float)1000 / (float)timeDiff) * testedPwds);

                System.out.println("Current Pass: " + String.copyValueOf(BrutePasswd.currPass) + " || ~ " + testedPwds + " Pass/Sec");
            }

            try {
                Thread.sleep(1000);
            } catch (Exception ignored) {

            }
        }
    }
}
