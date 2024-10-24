
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class SAESConsole {

    // S-box 和 inverse S-box
    private static final int[] SBOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
    private static final int[] INV_SBOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("输入明文 (16-bit 二进制字符串):");
        String plaintext = scanner.nextLine();

        System.out.println("输入密钥 (16-bit 二进制字符串):");
        String key = scanner.nextLine();

        String encryptedText = encryptBinary(plaintext, key);
        System.out.println("加密后的密文: " + encryptedText);

        String decryptedText = decryptBinary(encryptedText, key);
        System.out.println("解密后的明文: " + decryptedText);
    }

    // 加密
    public static String encryptBinary(String plaintext, String key) {
        int pt = Integer.parseInt(plaintext, 2);
        int k = Integer.parseInt(key, 2);

        int[] w = keyExpansion(k);

        int state = addRoundKey(pt, w[0], w[1]);
        state = nibbleSub(state);
        state = shiftRows(state);
        state = mixColumns(state);

        state = addRoundKey(state, w[2], w[3]);
        state = nibbleSub(state);
        state = shiftRows(state);

        int ciphertext = addRoundKey(state, w[4], w[5]);

        return String.format("%16s", Integer.toBinaryString(ciphertext)).replace(' ', '0');
    }

    // 解密
    public static String decryptBinary(String ciphertext, String key) {
        int ct = Integer.parseInt(ciphertext, 2);
        int k = Integer.parseInt(key, 2);

        int[] w = keyExpansion(k);

        int state = addRoundKey(ct, w[4], w[5]);
        state = invShiftRows(state);
        state = invNibbleSub(state);
        state = addRoundKey(state, w[2], w[3]);

        state = invMixColumns(state);
        state = invShiftRows(state);
        state = invNibbleSub(state);
        int plaintext = addRoundKey(state, w[0], w[1]);

        return String.format("%16s", Integer.toBinaryString(plaintext)).replace(' ', '0');
    }

    // 扩展密钥，生成 6 个 8-bit 轮密钥 w[0] 到 w[5]
    private static int[] keyExpansion(int key) {
        int[] w = new int[6];
        w[0] = (key >> 8) & 0xFF;
        w[1] = key & 0xFF;

        for (int i = 2; i < 6; i++) {
            if (i % 2 == 0) {
                w[i] = w[i - 2] ^ (0x80 >> (i / 2 - 1));
            } else {
                w[i] = w[i - 1] ^ w[i - 2];
            }
        }
        return w;
    }

    // 轮密钥加 (AddRoundKey)
    private static int addRoundKey(int state, int key1, int key2) {
        return state ^ ((key1 << 8) | key2);
    }

    // 半字节代替 (Nibble Substitution)
    private static int nibbleSub(int input) {
        int highNibble = (input >> 4) & 0xF;
        int lowNibble = input & 0xF;
        return (SBOX[highNibble] << 4) | SBOX[lowNibble];
    }

    // 逆半字节代替 (Inverse Nibble Substitution)
    private static int invNibbleSub(int input) {
        int highNibble = (input >> 4) & 0xF;
        int lowNibble = input & 0xF;
        return (INV_SBOX[highNibble] << 4) | INV_SBOX[lowNibble];
    }

    private static int shiftRows(int input) {
        return ((input & 0xF0) >> 4) | ((input & 0x0F) << 4);
    }

    private static int invShiftRows(int input) {
        return shiftRows(input);
    }

    private static int mixColumns(int input) {
        int a = input >> 4;
        int b = input & 0xF;
        return ((a ^ b) << 4) | a;
    }

    private static int invMixColumns(int input) {
        int a = input >> 4;
        int b = input & 0xF;
        return ((a ^ b) << 4) | b;
    }
}
