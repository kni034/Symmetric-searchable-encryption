import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.event.CaretListener;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;


public class main {
    public static void main(String[] args) {
        //server server = new server(32);

        //client alice = new client("alice123", "alicekey123", server, 32);
        //client bob = new client("bobID", "password123", server, 32);

        //File alicefile1 = new File("./resources/test2.txt");
        //File bobfile1 = new File("./resources/test2.txt");
        //File alicefile2 = new File("./resources/test3.txt");
        //File bobfile2 = new File("./resources/test4.txt");

        //uploadProtocol(alice, alicefile1);
        //uploadProtocol(bob, bobfile1);
        //uploadProtocol(alice, alicefile2);
        //uploadProtocol(bob, bobfile2);

        //searchProtocol(alice, "1234");
        //searchProtocol(bob, "123");
        loop();
    }

    public static void uploadProtocol(client cli,File f){
        cli.upload(f);
    }

    public static void searchProtocol(client client, String searchWord){
        client.search(searchWord);
    }

    public static void loop(){
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fc.setMultiSelectionEnabled(false);
        fc.showOpenDialog(null);
        File dir = fc.getSelectedFile();
        String path = dir.getAbsolutePath() + "/";
        System.out.println(path);
        Scanner sc = new Scanner(System.in);
        fc = new JFileChooser(dir);
        server server = new server(32, path);
        while(true){
            System.out.println("Username: ");
            String username = sc.nextLine();
            System.out.println("Password: ");
            String password = sc.nextLine();
            if (username == "" || password == ""){
                System.out.println("username or password cannot be empty");
                continue;
            }
            client client = new client(username, password, server, 32, path);
            while(true){
                System.out.println("You are logged in as " + client.getName() + " with userID: " + client.getID());
                System.out.println("If you want to uplaod a file press 'u'");
                System.out.println("If you want to search for a word press 's'");
                System.out.println("If you want to log out press 'l', or press 'q' to quit");
                String command = sc.nextLine();
                if(command.equals("u")){
                    fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    fc.setMultiSelectionEnabled(true);
                    fc.showOpenDialog(null);
                    File[] files = fc.getSelectedFiles();
                    for(File file : files){
                        uploadProtocol(client, file);
                    }
                }
                else if(command.equals("s")){
                    System.out.println("Keyword to search for: ");
                    String keyword = sc.nextLine();
                    searchProtocol(client, keyword);
                }
                else if(command.equals("l")){
                    break;
                }
                else if(command.equals("q")){
                    System.exit(0);
                }
                else {
                    System.out.println("Wrong command, try again");
                }
            }
        }

    }
}
