import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;

public class server {

    int blockSize = 44;
    int m = blockSize/2;
    private CryptoHelper ch;
    private static Charset charset = java.nio.charset.StandardCharsets.ISO_8859_1;

    public server(){
        ch = new CryptoHelper();
    }


    /*
    checks if the given file contains the encrypted search word from the given search token.
    input encrypted = the encrypted file to be searched, searchToken = the searchtoken with the encrypted searchword
    returns true if file contains searchword, false if not
     */
    public boolean checkMatch(File encrypted, String searchToken) {
        String keyword = searchToken.substring(0, blockSize);
        String k = searchToken.substring(blockSize);

        String fileString = null;
        try {
            fileString = Files.readString(Paths.get(encrypted.getAbsolutePath()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Encrypted keyword, not cleartext
        String L = keyword.substring(0,blockSize-m);
        String R = keyword.substring(m);

        for (int j = 0; j <= fileString.length() - 1;) {

            String word = fileString.substring(j, j + blockSize);

            String c1 = word.substring(0,blockSize-m);

            String c2 = word.substring(m);

            String s = new String(ch.XORByteArrays(c1.getBytes(charset), L.getBytes(charset)),charset);

            String fks = ch.sha512Hash(s + k).substring(0, m);

            String test = new String(ch.XORByteArrays(c2.getBytes(charset), fks.getBytes(charset)),charset);

            if(R.equals(test)){
                return true;
            }

            j = j + blockSize;
        }
        return false;
    }


}
