import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;

public class Server {

    public static boolean insecureCompare(byte[] a, byte[] b) throws InterruptedException {
        if (a.length != b.length) return false;

        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
            Thread.sleep(50);
        }
        return true;
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(9000), 0);

        byte[] real = new byte[20];

        server.createContext("/test", (HttpExchange exchange) -> {
            String query = exchange.getRequestURI().getQuery();

            String sigHex = query.split("signature=")[1];
            byte[] sig = hexToBytes(sigHex);

            boolean ok = false;
            try {
                ok = insecureCompare(sig, real);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            String response = ok ? "OK" : "FAIL";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        });

        server.start();
        System.out.println("Server running on http://localhost:9000/test");
    }

    static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return data;
    }
}