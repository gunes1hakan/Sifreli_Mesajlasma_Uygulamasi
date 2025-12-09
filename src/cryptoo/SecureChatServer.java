package cryptoo;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Sadece satır ileten çok basit bir chat server:
 *  - Şifreyi bilmez, dokunmaz.
 *  - Gelen her satırı tüm diğer client'lara broadcast eder.
 */
public class SecureChatServer {
    private final int port;
    private final List<ClientHandler> clients = new CopyOnWriteArrayList<>();

    public SecureChatServer(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("[Server] Listening on port " + port + "...");
            while (true) {
                Socket socket = server.accept();
                ClientHandler handler = new ClientHandler(socket, this);
                clients.add(handler);
                new Thread(handler, "ClientHandler-" + socket.getRemoteSocketAddress()).start();
            }
        }
    }

    void broadcast(String line, ClientHandler from) {
        for (ClientHandler c : clients) {
            if (c != from) c.send(line);
        }
    }

    void remove(ClientHandler handler) {
        clients.remove(handler);
        try { handler.close(); } catch (IOException ignored) {}
    }

    public static void main(String[] args) throws IOException {
        int port = 6000;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }
        new SecureChatServer(port).start();
    }

    static class ClientHandler implements Runnable {
        private final Socket socket;
        private final SecureChatServer server;
        private final BufferedReader in;
        private final PrintWriter out;

        ClientHandler(Socket socket, SecureChatServer server) throws IOException {
            this.socket = socket;
            this.server = server;
            this.in = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8));
            this.out = new PrintWriter(new OutputStreamWriter(
                    socket.getOutputStream(), StandardCharsets.UTF_8), true);
            System.out.println("[Server] Connected: " + socket.getRemoteSocketAddress());
        }

        void send(String line) {
            out.println(line);
        }

        @Override
        public void run() {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    server.broadcast(line, this);
                }
            } catch (IOException ignored) {
            } finally {
                System.out.println("[Server] Disconnected: " + socket.getRemoteSocketAddress());
                server.remove(this);
            }
        }

        void close() throws IOException {
            try { in.close(); } catch (Exception ignored) {}
            try { out.close(); } catch (Exception ignored) {}
            socket.close();
        }
    }
}
