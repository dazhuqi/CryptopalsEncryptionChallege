import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;

public class TimingAttack {
    private static final String TARGET = "http://localhost:9000/test";
    private static final String FILENAME = "foo";
    private static final int SAMPLES = 50;

    private static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // single response consuming time
    private static long measureOnce(String signature) {
        try {
            long start = System.nanoTime();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(TARGET + "?file=" + FILENAME + "&signature=" + signature))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            client.send(request, HttpResponse.BodyHandlers.discarding());

            return System.nanoTime() - start;

        } catch (Exception e) {
            return Long.MAX_VALUE;
        }
    }

    // mean
    private static long measureAvg(String signature) {
        long[] samples = new long[SAMPLES];

        for (int i = 0; i < SAMPLES; i++) {
            samples[i] = measureOnce(signature);
        }

        Arrays.sort(samples);

        // trimmed mean
        int start = SAMPLES / 5;
        int end = SAMPLES - SAMPLES / 5;

        long sum = 0;
        int count = 0;

        for (int i = start; i < end; i++) {
            sum += samples[i];
            count++;
        }

        return sum / count;
    }

    public static void main(String[] args) {

        System.out.println("[*] Timing Attack Starting...");

        byte[] known = new byte[20];

        // warm-up
        measureOnce("00");

        for (int pos = 0; pos < 20; pos++) {

            long bestScore = -1;
            int bestByte = 0;

            for (int b = 0; b < 256; b++) {

                known[pos] = (byte) b;
                String testHex = bytesToHex(known);

                long t = measureAvg(testHex);

                if (t > bestScore) {
                    bestScore = t;
                    bestByte = b;
                }
            }

            known[pos] = (byte) bestByte;

            System.out.printf(
                    "[+] pos=%d byte=%02x | time=%.2f ms | sig=%s%n",
                    pos + 1,
                    bestByte,
                    bestScore / 1_000_000.0,
                    bytesToHex(known)
            );
        }

        System.out.println("\n[!!!] Final signature: " + bytesToHex(known));
    }
}