import java.io.File;
import java.util.Arrays;


public class main {
    public static void main(String[] args) {
        client alice = new client("abc123");
        server server = new server();
        File f = alice.getLookup();
        alice.setLookup(f);

        CryptoHelper ch = new CryptoHelper();
        trivium tr = new trivium("aaaaaaaaaa","aaaaaaaaaa");
        System.out.println(Arrays.toString(tr.getNextNBits(100)));

    }
}
