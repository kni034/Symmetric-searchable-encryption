import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;


public class client {

    private static int blockSize = 32;
    private static int encryptedBlockSize = 44;
    private static int m = encryptedBlockSize/2;
    private String key;
    private HashMap<String, String> lookup;
    private static char filler = '*';
    private static String tmpFolder = "./resources/";
    private static SecretKeySpec secretKey;
    private static String initVector = "aaaaaaaaaaaaaaaa";
    private static IvParameterSpec iv;
    private CryptoHelper ch;
    private static Charset charset = java.nio.charset.StandardCharsets.ISO_8859_1;


    //initializes the sse with a secret key

    public client(String input){
        ch = new CryptoHelper();
        this.key = ch.sha512Hash(input);
        secretKey = new SecretKeySpec(key.substring(0,16).getBytes(), "AES");
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        lookup = new HashMap<String,String>();
    }

    //generates a search token to be sent to the server. includes encrypted search word and key k
    //input: keyword to be encrypted and made into a search token
    //returns the token as a string


    public String generateSearchToken(String keyword){
        keyword = correctLength(keyword);


        keyword = ch.encryptECB(keyword, secretKey);
        String L = keyword.substring(0,encryptedBlockSize-m);

        String k = ch.sha512Hash(L).substring(0, 10);


        String token = keyword + k;
        return token;
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
        trivium tr = new trivium(seed, initVector.substring(0, 10));

        File decrypted = new File(tmpFolder + encrypted.getName());

        try {

            String fileString = Files.readString(Paths.get(encrypted.getAbsolutePath()));
            byte[] fileBytes = fileString.getBytes(charset);

            FileWriter fileWriter = new FileWriter(decrypted);

            for (int i = 0; i <= fileString.length() - 1;) {
                String word = fileString.substring(i, i + encryptedBlockSize);
                String decryptedWord = decryptBlock(word,tr);
                decryptedWord = decryptedWord.replace("*", "");
                decryptedWord += " ";
                fileWriter.write(decryptedWord);

                i = i + encryptedBlockSize;
            }

            fileWriter.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    //java.nio.charset.StandardCharsets.ISO_8859_1

    //decrypts block,used during decrypting
    //input: word= block to be decrypted, randomStringGenerator = generator which generates s
    private String decryptBlock(String word, trivium tr){
        String C1 = word.substring(0,encryptedBlockSize-m);
        String C2 = word.substring(m);

        String s = new String(tr.getNextNBytes(encryptedBlockSize-m),charset);

        String L = new String(ch.XORByteArrays(C1.getBytes(charset), s.getBytes(charset)),charset);

        String k = ch.sha512Hash(L).substring(0, 10);
        String fks = ch.sha512Hash(s + k).substring(0, m);

        String R = new String(ch.XORByteArrays(C2.getBytes(charset), fks.getBytes(charset)),charset);

        String X = L + R;

        String W = ch.decryptECB(X, secretKey);

        return W;
    }

    //updates the lookup table with the given lookup file
    //input: lookup = lookup file


    public void setLookup(File lookup) {

        File toFile = new File(tmpFolder + ".lookupDecrypted");

        try {
            ch.decryptFile(lookup, toFile, iv, secretKey);

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
        File toFile = new File(tmpFolder + ".lookupEncrypted");

        ch.encryptFile(lookupFile, toFile, iv, secretKey);

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
        String numberOfFiles = "" + lookup.size();
        String seed = key.substring(0,10);
        seed = seed.substring(0, seed.length() - numberOfFiles.length());
        seed += numberOfFiles;

        trivium tr = new trivium(seed, initVector.substring(0, 10));
        File encrypted = new File(tmpFolder + clear.getName());
        try {

            Scanner fileReader = new Scanner(clear);
            fileReader.hasNextLine();
            FileWriter fileWriter = new FileWriter(encrypted);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                String[] words = data.split(" ");

                for(String word : words){
                    String encryptedWord = encryptWord(word,tr);
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
    private String encryptWord(String word, trivium tr) {
        word = correctLength(word);

        word = ch.encryptECB(word, secretKey);

        String L = word.substring(0,encryptedBlockSize-m);
        String R = word.substring(m);
        String k = ch.sha512Hash(L).substring(0, 10);

        String s = new String(tr.getNextNBytes(encryptedBlockSize-m),charset);

        String fks = ch.sha512Hash(s + k).substring(0, m);

        String C1 = new String(ch.XORByteArrays(L.getBytes(charset), s.getBytes(charset)),charset);
        String C2 = new String(ch.XORByteArrays(R.getBytes(charset), fks.getBytes(charset)),charset);

        String C = C1 + C2;
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


         //* Create an alphanumeric string generator.


        public RandomString(int length, Random random) {
            this(length, random, alphanum);
        }


         //* Create an alphanumeric strings from a secure generator.


        public RandomString(int length) {
            this(length, new SecureRandom());
        }


         //* Create session identifiers.


        public RandomString() {
            this(21);
        }

    }

}
