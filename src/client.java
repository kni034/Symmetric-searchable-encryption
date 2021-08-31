import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;



public class client {

    private static int blockSize = 24;
    private static int m = blockSize/2;
    private String key;
    private HashMap<String, String> lookup;
    private static char filler = '*';
    private static String tmpFolder = "./src/main/resources/tmp/";
    private static SecretKeySpec secretKey;


    //initializes the sse with a secret key


    public client(String key){
        this.key = key;
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(key.getBytes());

        this.key = md.toString();
        secretKey = new SecretKeySpec(key.getBytes(), "AES");
    }

    //generates a search token to be sent to the server. includes encrypted search word and key k
    //input: keyword to be encrypted and made into a search token
    //returns the token as a string


    public String generateSearchToken(String keyword){
        keyword = correctLength(keyword);

        //TODO encrypt with aes ecb
        keyword = gfg.permute(false, keyword);
        String L = keyword.substring(0,blockSize-m);
        int k = L.hashCode();


        String token = keyword + k;
        return token;
    }

    //adds the values of 2 bytes together to an int, and converts back to a byte
    //works like the modulo operation


    private byte f2plus(byte a, byte b){
        Integer c = a + b;
        return c.byteValue();
    }

    //subtracts the values of 2 bytes from each other to an int, and converts back to a byte
    //works like the modulo operation


    private byte f2minus(byte a, byte b){
        Integer c = a - b;
        return c.byteValue();
    }

    //decrypts a file encrypted by the same user, uses the lookup table
    //input: encrypted = file to be decrypted
    //returns decrypted file


    public File decryptFile(File encrypted){
        String hashed = Integer.toString(encrypted.hashCode());
        if (!lookup.containsKey(hashed)){
            System.out.println("key missing in lookup");
            return encrypted;
        }
        String seed = lookup.get(hashed);
        Random random = new Random(seed.hashCode());
        RandomString randomStringGenerator = new RandomString(m,random);

        File decrypted = new File(tmpFolder + encrypted.getName());

        try {

            String fileString = Files.readString(Paths.get(encrypted.getAbsolutePath()));

            FileWriter fileWriter = new FileWriter(decrypted);

            for (int i = 0; i <= fileString.length() - 1;) {
                String word = fileString.substring(i, i + blockSize);
                String decryptedWord = decryptBlock(word,randomStringGenerator);
                decryptedWord = decryptedWord.replace("*", "");
                decryptedWord += " ";
                fileWriter.write(decryptedWord);

                i = i + blockSize;
            }

            fileWriter.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    //decrypts block,used during decrypting
    //input: word= block to be decrypted, randomStringGenerator = generator which generates s


    private String decryptBlock(String word, RandomString randomStringGenerator){


        String C1 = word.substring(0,blockSize-m);
        String C2 = word.substring(m);

        String s = randomStringGenerator.nextString();

        byte[] sBytes = s.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes1 = C1.getBytes(StandardCharsets.UTF_8);

        byte[] LBytes = new byte[cipherBytes1.length];

        for (int i =0;i<cipherBytes1.length;i++){
            LBytes[i] = f2minus(cipherBytes1[i] , sBytes[i]);
        }

        String L = new String(LBytes, StandardCharsets.UTF_8);

        int k = L.hashCode();
        Random random = new Random(k);
        RandomString fkGenerator = new RandomString(blockSize-m,random);
        String fk = fkGenerator.nextString();

        byte[] cipherBytes2 = C2.getBytes(StandardCharsets.UTF_8);
        byte[] fkBytes = fk.getBytes(StandardCharsets.UTF_8);

        byte[] fsBytes = new byte[fkBytes.length];
        for (int i =0;i<fsBytes.length;i++){
            fsBytes[i] = f2plus(fkBytes[i] , sBytes[i]);
        }

        byte[] RBytes = new byte[cipherBytes2.length];

        for (int i =0;i<cipherBytes2.length;i++){
            RBytes[i] = f2minus(cipherBytes2[i] , fsBytes[i]);
        }

        String R = new String(RBytes, StandardCharsets.UTF_8);

        String X = L + R;

        //TODO decrypt with aes ecb
        String W = gfg.permute(true, X);

        return W;
    }

    //updates the lookup table with the given lookup file
    //input: lookup = lookup file


    public void setLookup(File lookup) {
        try {
            File toFile = new File(tmpFolder + ".lookupDecrypted");

            //TODO decrypt with aes cbc
            FileEncryptor.decryptFile(lookup, toFile,  key);
            File toRead = toFile;

            FileInputStream fis = new FileInputStream(toRead);
            ObjectInputStream ois = new ObjectInputStream(fis);

            HashMap<String,String> mapInFile=(HashMap<String,String>)ois.readObject();

            ois.close();
            fis.close();

            this.lookup = mapInFile;

            toFile.delete();
            lookup.delete();

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    //returns the lookup table as a file


    public File getLookup() {
        File lookupFile = new File(tmpFolder + ".lookupClear");

        try {
            FileOutputStream fos = new FileOutputStream(lookupFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(lookup);
            oos.flush();
            oos.close();
            fos.close();

        } catch(Exception e) {
            e.printStackTrace();
        }
        File toFile = null;
        try {
            toFile = new File(tmpFolder+".lookup");
            //TODO encrypt with aes cbc
            FileEncryptor.encryptFile(lookupFile, toFile, key);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        lookupFile.delete();

        return toFile;
    }

    //encrypts a file with the sse algorithm.
    //input: clear = file to be encrypted
    //returns the encrypted file


    public File encryptFile(File clear) {
        if(lookup == null){
            lookup = new HashMap<String,String>();
        }
        int numberOfFiles = lookup.size();
        String seed = key + numberOfFiles;

        Random random = new Random(seed.hashCode());
        RandomString randomStringGenerator = new RandomString(m,random);

        File encrypted = new File(tmpFolder + clear.getName());
        try {

            Scanner fileReader = new Scanner(clear);
            fileReader.hasNextLine();
            FileWriter fileWriter = new FileWriter(encrypted);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                String[] words = data.split(" ");

                for(String word : words){
                    String encryptedWord = encryptWord(word,randomStringGenerator);
                    fileWriter.write(encryptedWord);
                }
            }
            fileWriter.close();
            fileReader.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        lookup.put(Integer.toString(encrypted.hashCode()), seed);

        return encrypted;
    }

    //encrypts a block, used during encryption of file.
    //input: word = block to be encrypted, randomStringGenerator = generator that produces s


    private String encryptWord(String word, RandomString randomStringGenerator) {
        word = correctLength(word);

        //TODO encrypt with aes ecb
        word = gfg.permute(false, word);

        String L = word.substring(0,blockSize-m);
        String R = word.substring(m);
        int k = L.hashCode();

        String s = randomStringGenerator.nextString();

        Random random = new Random(k);
        RandomString fkGenerator = new RandomString(blockSize-m,random);
        String fk = fkGenerator.nextString();

        byte[] clearBytes1 = L.getBytes(StandardCharsets.UTF_8);
        byte[] clearBytes2 = R.getBytes(StandardCharsets.UTF_8);

        byte[] sBytes = s.getBytes(StandardCharsets.UTF_8);
        byte[] fkBytes = fk.getBytes(StandardCharsets.UTF_8);

        byte[] fsBytes = new byte[fkBytes.length];
        for (int i =0;i<fsBytes.length;i++){
            fsBytes[i] = f2plus(sBytes[i] , fkBytes[i]);
        }

        byte[] C1 = new byte[clearBytes1.length];
        byte[] C2 = new byte[clearBytes2.length];

        for (int i =0;i<clearBytes1.length;i++){
            C1[i] = f2plus(clearBytes1[i] , sBytes[i]);
        }
        for (int i =0;i<clearBytes2.length;i++){
            C2[i] = f2plus(clearBytes2[i] , fsBytes[i]);
        }

        String C1string = new String(C1, StandardCharsets.UTF_8);
        String C2string = new String(C2, StandardCharsets.UTF_8);

        String C = C1string + C2string;


        return C;
    }

    //converts a word to the length of the block size. uses * as filler characters
    //input: keyword = string to convert
    //returns string of correct length


    private String correctLength(String keyword) {
        while(keyword.length() < blockSize){
            keyword += filler;
        }
        while (keyword.length() > blockSize){
            keyword = keyword.substring(0, keyword.length() - 1);
        }

        return keyword;
    }

    private byte[] byteToBits(byte in){


        
        return null;
    }

    //class to generate random strings, used to generate s


    private static class RandomString {

         //* Generate a random string.


        public String nextString() {
            for (int idx = 0; idx < buf.length; ++idx)
                buf[idx] = symbols[random.nextInt(symbols.length)];
            return new String(buf);
        }

        public static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public static final String lower = upper.toLowerCase(Locale.ROOT);

        public static final String digits = "0123456789";

        public static final String alphanum = upper + lower + digits;

        private final Random random;

        private final char[] symbols;

        private final char[] buf;

        public RandomString(int length, Random random, String symbols) {
            if (length < 1) throw new IllegalArgumentException();
            if (symbols.length() < 2) throw new IllegalArgumentException();
            this.random = Objects.requireNonNull(random);
            this.symbols = symbols.toCharArray();
            this.buf = new char[length];
        }

*
         //* Create an alphanumeric string generator.


        public RandomString(int length, Random random) {
            this(length, random, alphanum);
        }

*
         //* Create an alphanumeric strings from a secure generator.


        public RandomString(int length) {
            this(length, new SecureRandom());
        }

*
         * Create session identifiers.


        public RandomString() {
            this(21);
        }

    }



    public String get_SHA_512_SecurePassword(String passwordToHash, String salt){
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++){
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

}
