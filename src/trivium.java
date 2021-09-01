import java.util.LinkedList;

public class trivium{

    //byte[] s1 = new byte[92];
    //byte[] s2 = new byte[83];
    //byte[] s3 = new byte[110];

    LinkedList<Byte> s1 = new LinkedList<>();
    LinkedList<Byte> s2 = new LinkedList<>();
    LinkedList<Byte> s3 = new LinkedList<>();


    public trivium(byte[] key, byte[] IV){

        if(key.length != 80){
            System.out.println("key length not 80, key length: " + key.length);
            return;
        }
        if(IV.length != 80){
            System.out.println("IV length not 80, IV length: " + IV.length);
            return;
        }

        fillRegisters(key, IV);
        initialRounds();
    }

    public trivium(String key, String IV){

        String keyBitString = convertStringToBinary(key);
        String ivBitString = convertStringToBinary(IV);

        byte[] keyArray = new byte[80]; //keyBitString.getBytes();
        byte[] ivArray = new byte[80]; //ivBitString.getBytes();

        for(int i=0;i<80;i++){
            // -48 because char "0" = byte 48, and char "1" = byte 49
            keyArray[i] = (byte) keyBitString.charAt(i);
            keyArray[i] -= 48;
            ivArray[i] = (byte) ivBitString.charAt(i);
            ivArray[i] -= 48;
        }

        if(keyArray.length != 80){
            System.out.println("key length not 80, key length: " + keyArray.length);
            return;
        }
        if(ivArray.length != 80){
            System.out.println("IV length not 80, IV length: " + ivArray.length);
            return;
        }

        fillRegisters(keyArray, ivArray);
        initialRounds();
    }

    public byte[] getNextNBits(int n){
        byte[] nextBits = new byte[n];
        for (int i=0;i<n;i++){
            nextBits[i] = getNextBit();
        }
        return nextBits;
    }

    public byte getNextBit(){

        /*
         * Used from the Trivium specifications, can also be used for
         * initializing the registers
         *
         * t1    =   s66 + s93
         * t2    =   s162 + s177
         * t3    =   s243 + s288
         *
         * z     =   t1 + t2 + t3
         *
         * t1    =   t1 + s91  s92 + s171
         * t2    =   t2 + s175  s176 + s264
         * t3    =   t3 + s286  s287 + s69
         * (s1; s2; : : : ; s93) --> (t3; s1; : : : ; s92)
         * (s94; s95; : : : ; s177) --> (t1; s94; : : : ; s176)
         * (s178; s279; : : : ; s288) --> (t2; s178; : : : ; s287)
         */


        byte t1, t2, t3;

        byte result = (byte) (s1.get(64) ^ s1.get(91)
                ^ s2.get(67) ^ s2.get(82)
                ^ s3.get(64) ^ s3.get(109));

        t1 = (byte) (s1.get(89) & s1.get(90));
        t1 ^= s2.get(76) ^ s1.get(64) ^ s1.get(91);

        t2 = (byte) (s2.get(80) & s2.get(81));
        t2 ^= s3.get(85) ^ s2.get(67) ^ s2.get(82);

        t3 = (byte) (s3.get(107) & s3.get(108));
        t3 ^= s1.get(67) ^ s3.get(64) ^ s3.get(109);

        s1.add(0,t3);
        s2.add(0,t1);
        s3.add(0,t2);

        s1.removeLast();
        s2.removeLast();
        s3.removeLast();

        return result;
    }

    private void fillRegisters(byte[] key, byte[] IV){
        //init first register
        for (int i = 0; i < key.length; i++) {
            s1.add(key[i]);
        }
        for(int i=0;i<12;i++){
            s1.add((byte) 0);
        }

        //init second register
        for (int i = 0; i < IV.length; i++) {
            s2.add(IV[i]);
        }
        for (int i=0;i<3;i++){
            s2.add((byte) 0);
        }

        //init third register
        for (int i = 0; i < 110 -3; i++) {
            s3.add((byte) 0);
        }
        for (int i=0;i<3;i++){
            s3.add((byte) 1);
        }
    }

    private void initialRounds(){
        for (int i = 0; i < (4 * 288); i++) {
            this.getNextBit();
        }
    }

    public static String convertStringToBinary(String input) {

        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();
        for (char aChar : chars) {
            result.append(
                    String.format("%8s", Integer.toBinaryString(aChar))   // char -> int, auto-cast
                            .replaceAll(" ", "0")                         // zero pads
            );
        }
        return result.toString();

    }
}