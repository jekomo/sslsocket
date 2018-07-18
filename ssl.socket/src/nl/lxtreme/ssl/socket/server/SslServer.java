package nl.lxtreme.ssl.socket.server;

import static nl.lxtreme.ssl.socket.SslUtil.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import nl.lxtreme.ssl.socket.SslContextProvider;

public class SslServer implements SslContextProvider {

    public static void main(String[] args) throws Exception {
//        if (args.length != 1) {
//            System.out.println("Usage: SslServer <port>\n");
//            System.exit(1);
//        }

        int port = Integer.parseInt("9000");

        new SslServer().run(port);
    }

    @Override
    public KeyManager[] getKeyManagers() throws GeneralSecurityException, IOException {
        return createKeyManagers("/Users/kabiruahmed/Documents/java-project/ssl-socket-demo/sslcert/server.jks", "kamok12345".toCharArray());
    }

    @Override
    public String getProtocol() {
        return "TLSv1.2";
    }

    @Override
    public TrustManager[] getTrustManagers() throws GeneralSecurityException, IOException {
        return createTrustManagers("/Users/kabiruahmed/Documents/java-project/ssl-socket-demo/sslcert/cacert.jks", "kamok12345".toCharArray());
    }

    public void run(int port) throws Exception {
        ServerSocket socket = createSSLSocket(port);

        System.out.println("Server started. Awaiting client...");

        try (SSLSocket client = (SSLSocket) socket.accept(); OutputStream os = client.getOutputStream(); InputStream is = client.getInputStream()) {
            System.out.printf("Client (%s) connected. Awaiting ping...%n", getPeerIdentity(client));

            byte[] buf = new byte[4];
            int read = is.read(buf);
            if (read != 4) {
                throw new RuntimeException("Not enough bytes read: " + read + ", expected 4 bytes!");
            }

            String command = new String(buf);
            if (!"ping".equals(command)) {
                throw new RuntimeException("Expected 'ping', but got '" + command + "'...");
            }

            System.out.println("Ping received. Sending pong...");

            os.write("pong".getBytes());
            os.flush();

            System.out.println("Pong written. Ending server...");
        }
    }

    private ServerSocket createSSLSocket(int port) throws Exception {
        SSLServerSocket socket = createSSLServerSocket(port, this);
        socket.setNeedClientAuth(true);
        return socket;
    }
}
