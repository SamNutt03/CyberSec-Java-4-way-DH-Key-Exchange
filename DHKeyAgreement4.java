import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

    /*
    * This program executes the Diffie-Hellman key agreement protocol between
    * 4 parties: Alice, Bob, Carol and David using a shared 2048-bit DH parameter.
    */
    public class DHKeyAgreement4 {
        private DHKeyAgreement4() {}
        public static void main(String argv[]) throws Exception {
            //Key generation and initialisation is the same code formatting as used in the lab - as instructed
            System.out.println("ALICE: Generate DH keypair ...");
            KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
            aliceKpairGen.initialize(2048);
            KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

            DHParameterSpec dhParamShared = 
                ((DHPublicKey) aliceKpair.getPublic()).getParams();

            System.out.println("BOB: Generate DH keypair ...");
            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamShared);
            KeyPair bobKpair = bobKpairGen.generateKeyPair();

            System.out.println("CAROL: Generate DH keypair ...");
            KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
            carolKpairGen.initialize(dhParamShared);
            KeyPair carolKpair = carolKpairGen.generateKeyPair();

            System.out.println("DAVID: Generate DH keypair ...");
            KeyPairGenerator davidKpairGen = KeyPairGenerator.getInstance("DH");
            davidKpairGen.initialize(dhParamShared);
            KeyPair davidKpair = davidKpairGen.generateKeyPair();

            System.out.println("ALICE: Initialize ...");
            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
            aliceKeyAgree.init(aliceKpair.getPrivate());

            System.out.println("BOB: Initialize ...");
            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKpair.getPrivate());

            System.out.println("CAROL: Initialize ...");
            KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
            carolKeyAgree.init(carolKpair.getPrivate());

            System.out.println("DAVID: Initialize ...");
            KeyAgreement davidKeyAgree = KeyAgreement.getInstance("DH");
            davidKeyAgree.init(davidKpair.getPrivate());

            //Intermediate step 1: Each party combines their key with another party
            Key ab = aliceKeyAgree.doPhase(bobKpair.getPublic(), false);
            Key bc = bobKeyAgree.doPhase(carolKpair.getPublic(), false);
            Key cd = carolKeyAgree.doPhase(davidKpair.getPublic(), false);
            Key da = davidKeyAgree.doPhase(aliceKpair.getPublic(), false);

            //Intermediate step 2: Intermediate results from step 1 are exchanged and combined with another party
            Key ac = aliceKeyAgree.doPhase(cd, false);
            Key bd = bobKeyAgree.doPhase(da, false);
            Key ca = carolKeyAgree.doPhase(ab, false);
            Key db = davidKeyAgree.doPhase(bc, false);

            //Step 3: Combines the intermediate keys with the parties own key to compute the shared secret
            aliceKeyAgree.doPhase(db, true);
            bobKeyAgree.doPhase(ac, true);
            carolKeyAgree.doPhase(bd, true);
            davidKeyAgree.doPhase(ca, true);

            // Alice, Bob and Carol compute their secrets
            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            System.out.println("Bob secret: " + toHexString(bobSharedSecret));
            byte[] carolSharedSecret = carolKeyAgree.generateSecret();
            System.out.println("Carol secret: " + toHexString(carolSharedSecret));
            byte[] davidSharedSecret = davidKeyAgree.generateSecret();
            System.out.println("David secret: " + toHexString(davidSharedSecret));

            // Compare Alice and Bob
            if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
                throw new Exception("Alice and Bob differ");
            System.out.println("Alice and Bob are the same");
            // Compare Bob and Carol
            if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
                throw new Exception("Bob and Carol differ");
            System.out.println("Bob and Carol are the same");
            // Compare Carol and David
            if (!java.util.Arrays.equals(carolSharedSecret, davidSharedSecret))
                throw new Exception("Carol and David differ");
            System.out.println("Carol and David are the same");
        }

        private static void byte2hex(byte b, StringBuffer buf) {
            char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            int high = ((b & 0xf0) >> 4);
            int low = (b & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }

        private static String toHexString(byte[] block) {
            StringBuffer buf = new StringBuffer();
            int len = block.length;
            for (int i = 0; i < len; i++) {
                byte2hex(block[i], buf);
                if (i < len - 1) {
                    buf.append(":");
                }
            }
            return buf.toString();
        }
    }
