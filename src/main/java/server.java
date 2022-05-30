import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;



public class server {

    int blockSize;
    int m;
    private CryptoHelper ch;
    private static Charset charset = StandardCharsets.ISO_8859_1;
    private String path = "./resources/serverStorage/";

    public server(int blockSize){
        ch = new CryptoHelper();
        this.blockSize = blockSize;
        m = blockSize /2;
    }

    public server(int blockSize, String folderPath){
        ch = new CryptoHelper();
        this.blockSize = blockSize;
        m = blockSize /2;
        this.path = folderPath + "serverStorage/";
    }

    //searches through users directory and returns files where searchword is included
    public File[] search(String userID, String token){
        String userPath = path + userID;
        File userDir = new File(userPath);
        userDir.mkdirs();
        File[] files = userDir.listFiles();

        ArrayList<File> returnFiles = new ArrayList<>();

        for(File file : files){
            if(file.getName().equals(".lookup")){
                continue;
            }
            if(checkMatch(file, token)){
                returnFiles.add(file);
            }
        }
        if (returnFiles.size() != 0){

            returnFiles.add(new File(userPath + "/.lookup"));
        }
        File[] returnArray = returnFiles.toArray(new File[0]);
        return returnArray;
    }

    public void upload(String userID, File file, File lookup){
        Path userPath = Paths.get(path + userID);
        Path originalPath = Paths.get(file.getPath());
        Path lookupPath = Paths.get(lookup.getPath());
        try {
            Files.createDirectories(userPath);

            Files.move(originalPath, userPath.resolve(originalPath.getFileName()),
                    StandardCopyOption.REPLACE_EXISTING);

            Files.move(lookupPath, userPath.resolve(lookupPath.getFileName()),
                    StandardCopyOption.REPLACE_EXISTING);
        }
        catch (Exception e){
            e.printStackTrace();
        }

    }


    public File getLookup(String userID){
        Path userPath = Paths.get(path + userID);

        try {
            Files.createDirectories(userPath);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        Path lookupPath = Paths.get(path + userID).resolve(".lookup");
        File lookup = lookupPath.toFile();

        if (lookup.length() == 0){
          return null;
        }
        return lookup;
    }

    /*
    checks if the given file contains the encrypted search word from the given search token.
    input encrypted = the encrypted file to be searched, searchToken = the searchtoken with the encrypted searchword
    returns true if file contains searchword, false if not
     */
    private boolean checkMatch(File encrypted, String searchToken) {
        String keyword = searchToken.substring(0, blockSize);
        String k = searchToken.substring(blockSize);

        String fileString = null;
        try {
            fileString = Files.readString(Paths.get(encrypted.getAbsolutePath()), charset);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Encrypted keyword, not cleartext
        String L = keyword.substring(0, blockSize -m);
        String R = keyword.substring(m);

        for (int j = 0; j <= fileString.length() - 1;) {

            String word = fileString.substring(j, j + blockSize);

            String c1 = word.substring(0, blockSize -m);

            String c2 = word.substring(m);

            String s = new String(ch.XORByteArrays(c1.getBytes(charset), L.getBytes(charset)), charset);

            String fks = new String(ch.calculateHMAC(s.getBytes(),k.getBytes()),charset).substring(0,blockSize-m);

            String test = new String(ch.XORByteArrays(c2.getBytes(charset), fks.getBytes(charset)), charset);

            if(R.equals(test)){
                return true;
            }

            j = j + blockSize;
        }
        return false;
    }
}
