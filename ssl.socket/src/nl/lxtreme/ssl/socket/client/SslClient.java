package nl.lxtreme.ssl.socket.client;

import static nl.lxtreme.ssl.socket.SslUtil.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import nl.lxtreme.ssl.socket.SslContextProvider;
import nl.lxtreme.ssl.socket.SslUtil;
import org.jpos.iso.ISOMsg;
import org.jpos.iso.packager.GenericPackager;

public class SslClient implements SslContextProvider {

    public static void main(String[] args) throws Exception {
//        if (args.length != 2) {
//            System.out.println("Usage: SslClient <host> <port>\n");
//            System.exit(1);
//        }

        String host = "196.6.103.73";
        int port = Integer.parseInt("5043");

        new SslClient().run(host, port);
    }

    @Override
    public KeyManager[] getKeyManagers() throws GeneralSecurityException, IOException {
        return createKeyManagers("/Users/kabiruahmed/Documents/java-project/ssl-socket-demo/sslcert/keystore.jks", "changeit".toCharArray());
    }

    @Override
    public String getProtocol() {
        return "TLSv1.2";
    }

    @Override
    public TrustManager[] getTrustManagers() throws GeneralSecurityException, IOException {
        return createTrustManagers("jssecacerts", "changeit".toCharArray());
    }

    public void run(String host, int port) throws Exception {
        try (SSLSocket socket = createSSLSocket(host, port); OutputStream os = socket.getOutputStream(); InputStream is = socket.getInputStream()) {

            System.out.println(socket.isConnected());
            System.out.printf("Connected to server (%s). Writing ping...%n", getPeerIdentity(socket));
            GenericPackager packager = new GenericPackager("basic.xml");

            // Create ISO Message
            ISOMsg isoMsg = new ISOMsg();
            isoMsg.setPackager(packager);
            isoMsg.setMTI("0200");
            isoMsg.set(3, "201234");
            isoMsg.set(4, "10000");
            isoMsg.set(7, "110722180");
            isoMsg.set(11, "123456");
            isoMsg.set(44, "A5DFGR");
            isoMsg.set(105, "ABCDEFGHIJ 1234567890");

            // print the DE list
            //logISOMsg(isoMsg);

            // Get and print the output result
            byte[] data = isoMsg.pack();
            System.out.println("RESULT : " + new String(data));

            os.write(data);

//            os.write("ping".getBytes());
//            os.flush();
//
//            System.out.println("Ping written, awaiting pong...");
//
//            byte[] buf = new byte[4];
//            int read = is.read(buf);
//            if (read != 4) {
//                throw new RuntimeException("Not enough bytes read: " + read + ", expected 4 bytes!");
//            }
//
//            String response = new String(buf);
//            if (!"pong".equals(response)) {
//                throw new RuntimeException("Expected 'pong', but got '" + response + "'...");
//            }
//
//            System.out.println("Pong obtained! Ending client...");
        }
    }

    private SSLSocket createSSLSocket(String host, int port) throws Exception {
        return SslUtil.createSSLSocket(host, port, this);
    }
}
