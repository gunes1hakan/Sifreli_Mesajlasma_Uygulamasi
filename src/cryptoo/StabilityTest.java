package cryptoo;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Verifies that the Reader Loop logic does not crash on exceptions.
 * Simulates the exact logic used in SecureChatClient.
 */
public class StabilityTest {

    public static void main(String[] args) {
        System.out.println("=== STABILITY TEST STARTED ===");

        try {
            testReaderLoopRecovery();
            System.out.println("RESULT: STABILITY PASS \u2705");
        } catch (Exception e) {
            System.err.println("RESULT: STABILITY FAIL \u274C");
            e.printStackTrace();
        }
    }

    /**
     * Simulates the loop:
     * 1. Good line
     * 2. Bad line (causes Exception)
     * 3. Good line
     * 
     * If the loop exits after step 2, test fails.
     */
    private static void testReaderLoopRecovery() throws Exception {
        // Prepare input: Good, Bad, Good
        String inputData = "Line1|Good\n" +
                "Line2|Bad\n" +
                "Line3|Good\n";

        BufferedReader in = new BufferedReader(
                new InputStreamReader(
                        new ByteArrayInputStream(inputData.getBytes(StandardCharsets.UTF_8))));

        boolean[] received3 = { false };

        // The LOOP logic (Mock of SecureChatClient.readerLoop)
        try {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("DEBUG: Socket read line: " + line);
                try {
                    mockHandleIncoming(line);
                    if (line.contains("Line3"))
                        received3[0] = true;
                } catch (Throwable t) {
                    System.err.println("CRITICAL: Error processing incoming line: " + t.getMessage());
                    // In real app: append to chatArea
                    if (!t.getMessage().contains("Simulated Crash")) {
                        throw new RuntimeException("Unexpected error type: " + t);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Socket IO Exception: " + e.getMessage());
        }

        if (!received3[0]) {
            throw new RuntimeException("Loop died after Line2! Line3 was not processed.");
        }
        System.out.println("Success: Loop survived the crash and processed Line3.");
    }

    private static void mockHandleIncoming(String line) {
        if (line.contains("Bad")) {
            throw new RuntimeException("Simulated Crash (e.g. Mac Check Failed)");
        }
        System.out.println("Processed: " + line);
    }
}
