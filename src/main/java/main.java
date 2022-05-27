import javax.swing.*;
import java.io.File;
import java.util.Scanner;


public class main {

    static int blockSize = 32;

    public static void main(String[] args) {

        loop();
    }

    public static void uploadProtocol(client cli,File f){
        cli.upload(f);
    }

    public static void searchProtocol(client client, String searchWord){
        client.search(searchWord);
    }

    public static void loop(){
        Scanner sc = new Scanner(System.in);
        System.out.println("Before we start, you have to choose a working directory.");
        System.out.println("This is where the server 'stores' files and downloads them to.");
        System.out.println("It is highly recommended that you choose an empty directory, or create a new one");
        System.out.println("You can open the directory while the program runs to see what is going on");
        System.out.println("Press 'Enter' to continue, this opens a window to choose directory");

        sc.nextLine();

        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fc.setMultiSelectionEnabled(false);
        fc.showOpenDialog(null);
        File dir = fc.getSelectedFile();
        String path = dir.getAbsolutePath() + "/";
        System.out.println(path);

        fc = new JFileChooser(dir);
        server server = new server(blockSize, path);

        while(true){

            System.out.println("Username: ");
            String username = sc.nextLine();
            System.out.println("Password: ");
            String password = sc.nextLine();
            if (username.equals("") || password.equals("")){
                System.out.println("username or password cannot be empty");
                continue;
            }
            client client = new client(username, password, server, blockSize, path);
            while(true){

                System.out.println("You are logged in as " + client.getName());
                System.out.println("If you want to uplaod a file press 'u' (select multiple files by holding 'ctrl' while selecting, or 'ctrl' + 'a' to select all)");
                System.out.println("If you want to search for a word press 's'");
                System.out.println("If you want to log out press 'l', or press 'q' to quit");
                String command = sc.nextLine();
                if(command.equals("u")){
                    fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    fc.setMultiSelectionEnabled(true);
                    fc.showOpenDialog(null);
                    File[] files = fc.getSelectedFiles();

                    for (File file : files) {
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
