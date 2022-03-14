import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class main {
    public static void main(String[] args) {
        server server = new server(32);

        client alice = new client("alice123", "alicekey123", server, 32);
        client bob = new client("bobID", "password123", server, 32);

        File alicefile1 = new File("./resources/test1.txt");
        //File bobfile1 = new File("./resources/test2.txt");
        //File alicefile2 = new File("./resources/test3.txt");
        //File bobfile2 = new File("./resources/test4.txt");

        uploadProtocol(alice, alicefile1);
        //uploadProtocol(bob, bobfile1);
        //uploadProtocol(alice, alicefile2);
        //uploadProtocol(bob, bobfile2);

        searchProtocol(alice, "123");
        searchProtocol(bob, "123");
    }

    public static void uploadProtocol(client cli,File f){
        cli.upload(f);
    }

    public static void searchProtocol(client client, String searchWord){
        client.search(searchWord);
    }

}
