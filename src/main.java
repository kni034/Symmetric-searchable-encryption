import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class main {
    public static void main(String[] args) {


        client alice = new client("abc123");
        server server = new server();
        File f = alice.getLookup();
        alice.setLookup(f);
        File test = alice.encryptFile( new File("./resources/test.txt"));
        File testLookup = alice.getLookup();
        alice.setLookup(testLookup);
        String token = alice.generateSearchToken(" ");
        System.out.println(server.checkMatch(test, token));
        File test123 = alice.decryptFile(test);


        /*
        SecretKeySpec secretKey = new SecretKeySpec("aaaaaaaaaaaaaaaa".getBytes(), "AES");
        Charset charset = java.nio.charset.StandardCharsets.ISO_8859_1;
        CryptoHelper ch = new CryptoHelper();
        String a = "abcde***************************";
        System.out.println(a);
        System.out.println(a.length());
        trivium tr = new trivium("aaaaaaaaaa","aaaaaaaaaa");

        String enc = ch.encryptECB(a, secretKey);
        System.out.println(enc);
        System.out.println(enc.length());

        String b = new String(tr.getNextNBytes(44), charset);
        System.out.println(b);
        System.out.println(b.length());

        String c = new String(ch.XORByteArrays(enc.getBytes(charset), b.getBytes(charset)),charset);
        System.out.println(c);
        System.out.println(c.length());

        String d = new String(ch.XORByteArrays(c.getBytes(charset), b.getBytes(charset)), charset);
        System.out.println(d);
        System.out.println(d.length());

        String dec = ch.decryptECB(d, secretKey);
        System.out.println(dec);
        System.out.println(dec.length());




        /*

        System.out.println(Arrays.toString(tr.getNextNBits(10)));

        SecretKeySpec secretKey = new SecretKeySpec("aaaaaaaaaaaaaaaa".getBytes(), "AES");

         */


/*


        String o = "0123456776543210";
        String o2 = "01234567765432100123456776543210";
        String o3 = "012345677654321001234567765432100123456776543210";
        String o4 = "0123456776543210012345677654321001234567765432100123456776543210";
        String o5 = "01234567765432100123456776543210012345677654321001234567765432100123456776543210";
        System.out.println("original word: " + o);
        System.out.println(o.length());

        String c = ch.encryptECB(o, secretKey);
        System.out.println("encrypted: " + c);
        System.out.println(c.length() - 16);

        String d = ch.encryptECB(o2, secretKey);
        System.out.println("encrypted: " + d);
        System.out.println(d.length() - 32);

        String e = ch.encryptECB(o3, secretKey);
        System.out.println("encrypted: " + e);
        System.out.println(e.length() - 48);

        String f = ch.encryptECB(o4, secretKey);
        System.out.println("encrypted: " + f);
        System.out.println(f.length() - 64);

        String g = ch.encryptECB(o5, secretKey);
        System.out.println("encrypted: " + g);
        System.out.println(f.length() - 80);


        String a = ch.encryptECB(o, secretKey);
        System.out.println("encrypted: " + a);
        System.out.println(a.length());

        String b = ch.decryptECB(a, secretKey);
        System.out.println("decrypted: " + b);
        System.out.println(b.length());


         */



    }
}
