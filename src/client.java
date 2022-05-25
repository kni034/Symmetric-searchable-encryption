import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;


public class client {

    private static int blockSize;
    private static int m;
    private String key;
    private HashMap<String, String> lookup;
    private static char filler = '*';
    private String tmpFolder = "./resources/";
    private String userPath = "./resources/clientStorage/";
    private SecretKeySpec secretKey;
    private String initVector;
    private IvParameterSpec iv;
    private CryptoHelper ch;
    private static Charset charset = StandardCharsets.UTF_8;
    private static Charset encryptedCharset = StandardCharsets.ISO_8859_1;
    private String userID;
    private String name;
    private server server;


    //initializes the sse with a secret key
    public client(String name, String userkey, server server, int blockSize){
        this.blockSize = blockSize;
        ch = new CryptoHelper();
        this.m = blockSize/2;
        this.server = server;
        this.userID = new String(ch.calculateHMAC(name.getBytes(),userkey.getBytes()), StandardCharsets.UTF_8);
        this.name = name;
        this.key = ch.sha512Hash(userkey);
        secretKey = new SecretKeySpec(key.substring(0,16).getBytes(), "AES");
        initVector = key.substring(16,32);
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        lookup = new HashMap<>();
        initClientFolder();
    }
    public client(String name, String userkey, server server, int blockSize, String folderPath){
        this.tmpFolder = folderPath;
        this.userPath = folderPath + "clientStorage/";

        this.blockSize = blockSize;
        ch = new CryptoHelper();
        this.m = blockSize/2;
        this.server = server;
        this.userID = new String(ch.calculateHMAC(name.getBytes(),userkey.getBytes()), StandardCharsets.UTF_8);
        this.name = name;
        this.key = ch.sha512Hash(userkey);
        secretKey = new SecretKeySpec(key.substring(0,16).getBytes(), "AES");
        initVector = key.substring(16,32);
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        lookup = new HashMap<>();
        initClientFolder();
    }

    public String getName(){
        return name;
    }

    public String getID() {
        return name;
    }

    private void initClientFolder(){
        Path clientPath = Paths.get(userPath + name);
        try {
            Files.createDirectories(clientPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }


    //generates a search token to be sent to the server. includes encrypted search word and key k
    //input: keyword to be encrypted and made into a search token
    //returns the token as a string
    private String[] generateSearchTokens(String word){
        String[] keywords = separateWords(word);

        ArrayList<String> tokens = new ArrayList<>();

        for (String keyword : keywords) {
            keyword = ch.encryptECB(keyword, secretKey);
            String L = keyword.substring(0, blockSize - m);

            String k = new String(ch.calculateHMAC(L.getBytes(),key.getBytes())).substring(0,10);
            //String k = ch.sha512Hash(L + key).substring(0, 10);


            String token = keyword + k;
            tokens.add(token);
        }

        return tokens.toArray(new String[0]);
    }



    private void decryptAllFiles(File[] files){
        if (files.length == 0){
            return;
        }
        ArrayList<File> fileList = new ArrayList<>();
        Collections.addAll(fileList, files);
        for(File file: files){
            if(file.getName().equals(".lookup")){
                setLookup(file);
                fileList.remove(file);
            }
        }

        for(File file: fileList){
            File g = decryptFile(file);
            g.renameTo(new File(userPath + name + "/" + file.getName()));
        }
    }

    //decrypts a file encrypted by the same user, uses the lookup table
    //input: encrypted = file to be decrypted
    //returns decrypted file
    private File decryptFile(File encrypted){
        String hashed = ch.fileChecksum(encrypted);
        if (!lookup.containsKey(hashed)){
            System.out.println("key missing in lookup");
            return encrypted;
        }
        String seed = lookup.get(hashed);
        trivium tr = new trivium(seed, initVector.substring(0, 10));

        File decrypted = new File(tmpFolder + encrypted.getName());

        try {

            String fileString = Files.readString(Paths.get(encrypted.getAbsolutePath()), encryptedCharset);

            FileWriter fileWriter = new FileWriter(decrypted);

            for (int i = 0; i <= fileString.length() - 1;) {
                String word = fileString.substring(i, i + blockSize);
                String decryptedWord = decryptBlock(word,tr);
                decryptedWord = removePadding(decryptedWord);
                fileWriter.write(decryptedWord);

                i = i + blockSize;
            }

            fileWriter.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        //encrypted.delete();

        return decrypted;
    }

    private String removePadding(String word){
        String paddingLength = word.substring(word.length()-2);
        int paddingNum = Integer.parseInt(paddingLength);
        if (paddingNum == -1){
            paddingNum = 0;
            String originalWord = word.substring(0,word.length() - 2 - paddingNum); // padding = -1 means that it is part of a bigger word, no space added
            return originalWord;
        }

        String originalWord = word.substring(0,word.length() - 2 - paddingNum);
        originalWord += " ";
        return originalWord;

    }

    //java.nio.charset.encryptedCharset

    //decrypts block,used during decrypting
    //input: word= block to be decrypted, randomStringGenerator = generator which generates s
    private String decryptBlock(String word, trivium tr){
        String C1 = word.substring(0,blockSize-m);
        String C2 = word.substring(m);

        String s = new String(tr.getNextNBytes(blockSize-m),encryptedCharset);

        String L = new String(ch.XORByteArrays(C1.getBytes(encryptedCharset), s.getBytes(encryptedCharset)),encryptedCharset);

        String k = new String(ch.calculateHMAC(L.getBytes(),key.getBytes())).substring(0,10);
        String fks = new String(ch.calculateHMAC(s.getBytes(),k.getBytes()), encryptedCharset).substring(0,blockSize-m);


        String R = new String(ch.XORByteArrays(C2.getBytes(encryptedCharset), fks.getBytes(encryptedCharset)),encryptedCharset);

        String X = L + R;

        String W = ch.decryptECB(X, secretKey);

        return W;
    }

    //updates the lookup table with the given lookup file
    //input: lookup = lookup file


    private void setLookup(File lookup) {

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
            //lookup.delete();

        } catch(Exception e) {
            e.printStackTrace();
        }
    }


    //returns the lookup table as a file

    private File getLookup() {
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
        File toFile = new File(tmpFolder + ".lookup");

        ch.encryptFile(lookupFile, toFile, iv, secretKey);

        lookupFile.delete();

        return toFile;
    }

    public void search(String searchWord){
        String[] tokens = generateSearchTokens(searchWord);
        List<File> matches = Arrays.asList(server.search(getID(),tokens[0]));
        for (String token:tokens) {
            File[] files = server.search(getID(), token);
            matches.retainAll(Arrays.asList(files));
        }
        decryptAllFiles(matches.toArray(new File[0]));
        System.out.println("Client: search successful, found "+ matches.size() + " matches");
    }

    public void upload(File file){
        File oldLookup = server.getLookup(getID());
        if(oldLookup != null){
            setLookup(oldLookup);
        }

        File encrypted = encryptFile(file);
        File lookup = getLookup();
        server.upload(getID(), encrypted, lookup);
        //System.out.println("Client: upload successful");
    }

    //encrypts a file with the sse algorithm.
    //input: clear = file to be encrypted
    //returns the encrypted file
    private File encryptFile(File clear) {
        if(lookup == null){
            lookup = new HashMap<>();
        }

        byte[] seed = new byte[10];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        String seed_string = new String(seed, StandardCharsets.ISO_8859_1);

        trivium tr = new trivium(seed_string, initVector.substring(0, 10));
        File encrypted = new File(tmpFolder + clear.getName());
        try {
            Scanner fileReader = new Scanner(clear);
            fileReader.hasNextLine();
            FileOutputStream fileWriter = new FileOutputStream(encrypted);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                String[] words = data.split(" ");

                for(String word : words){
                    String[] splitWords = separateWords(word);
                    for(String w: splitWords) {
                        String encryptedWord = encryptWord(w, tr);
                        fileWriter.write(encryptedWord.getBytes(encryptedCharset));
                    }
                }
            }
            fileWriter.close();
            fileReader.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        lookup.put(ch.fileChecksum(encrypted), seed_string);

        return encrypted;
    }

    //encrypts a block, used during encryption of file.
    //input: word = block to be encrypted, randomStringGenerator = generator that produces s
    private String encryptWord(String w, trivium tr) {
        String word = ch.encryptECB(w, secretKey);

        String L = word.substring(0,blockSize-m);
        String R = word.substring(m);

        String k = new String(ch.calculateHMAC(L.getBytes(),key.getBytes())).substring(0,10);
        String s = new String(tr.getNextNBytes(blockSize-m),encryptedCharset);

        String fks = new String(ch.calculateHMAC(s.getBytes(),k.getBytes()),encryptedCharset).substring(0,blockSize-m);

        String C1 = new String(ch.XORByteArrays(L.getBytes(encryptedCharset), s.getBytes(encryptedCharset)),encryptedCharset);
        String C2 = new String(ch.XORByteArrays(R.getBytes(encryptedCharset), fks.getBytes(encryptedCharset)),encryptedCharset);

        String C = C1 + C2;
        return C;
    }


    private String[] separateWords(String word){
        ArrayList<String> words = new ArrayList<>();
        byte[] bytes = word.getBytes(StandardCharsets.UTF_8);
        ArrayList<Byte> wordBytes = new ArrayList<>();
        for (byte b : bytes){
            wordBytes.add(b);
        }
        while(wordBytes.size() > blockSize-2){

            //ArrayList<Byte> a = new ArrayList<>();
            byte[] a = new byte[blockSize];

            for(int i=0;i<blockSize-2;i++){
                a[i] = wordBytes.get(0);
                wordBytes.remove(0);
            }

                a[blockSize-2] = ("-".getBytes(charset)[0]);
                a[blockSize-1] = ("1".getBytes(charset)[0]);


            words.add(new String(a, charset));
        }
        if(wordBytes.size() != 0) {
            int counter = 0;
            while (wordBytes.size() < blockSize - 2) {
                wordBytes.add("*".getBytes(charset)[0]);
                counter++;
            }
            String lastWord = byteListToString(wordBytes, charset);
            lastWord += String.format("%02d", counter);
            words.add(lastWord);
        }
        return words.toArray(new String[0]);
    }

    private static String byteListToString(List<Byte> l, Charset charset) {
        if (l == null) {
            return "";
        }
        byte[] array = new byte[l.size()];
        int i = 0;
        for (Byte current : l) {
            array[i] = current;
            i++;
        }
        return new String(array, charset);
    }

}
