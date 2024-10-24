//public class SAESCore {
//
//    // S-box 表
//    private static final int[] SBOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
//    private static final int[] INV_SBOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};
//    private static final int[] RCON = {0x80, 0x30};
//
//    public static void main(String[] args) {
//        String key = "0010001111111111"; // 16-bit binary key
//        String plaintext = "0110000011011111"; // 16-bit binary plaintext
//
//        String ciphertext = encryptBinary(plaintext, key);
//        System.out.println("Ciphertext: " + ciphertext);
//
//        String decryptedText = decryptBinary(ciphertext, key);
//        System.out.println("Decrypted Text: " + decryptedText);
//
//        if (plaintext.equals(decryptedText)) {
//            System.out.println("Test Passed: Encryption and decryption are consistent.");
//        } else {
//            System.out.println("Test Failed: Decrypted text does not match the original plaintext.");
//        }
//    }
//
//    public static String encryptBinary(String plaintext, String key) {
//        int pt = Integer.parseInt(plaintext, 2);
//        int k = Integer.parseInt(key, 2);
//
//        int[] w = keyExpansion(k);
//        int state = addRoundKey(pt, w[0], w[1]);
//
//        state = nibbleSub(state);
//        state = shiftRows(state);
//        state = mixColumns(state);
//        state = addRoundKey(state, w[2], w[3]);
//
//        state = nibbleSub(state);
//        state = shiftRows(state);
//        int ciphertext = addRoundKey(state, w[4], w[5]);
//
//        return String.format("%16s", Integer.toBinaryString(ciphertext)).replace(' ', '0');
//    }
//
//    public static String decryptBinary(String ciphertext, String key) {
//        int ct = Integer.parseInt(ciphertext, 2);
//        int k = Integer.parseInt(key, 2);
//
//        int[] w = keyExpansion(k);
//
//        int state = addRoundKey(ct, w[4], w[5]);
//        state = invShiftRows(state);
//        state = invNibbleSub(state);
//        state = addRoundKey(state, w[2], w[3]);
//
//        state = invMixColumns(state);
//        state = invShiftRows(state);
//        state = invNibbleSub(state);
//        int plaintext = addRoundKey(state, w[0], w[1]);
//
//        return String.format("%16s", Integer.toBinaryString(plaintext)).replace(' ', '0');
//    }
//
//    private static int[] keyExpansion(int key) {
//        int[] w = new int[6];
//        w[0] = (key >> 8) & 0xFF;
//        w[1] = key & 0xFF;
//
//        for (int i = 2; i < 6; i++) {
//            if (i % 2 == 0) {
//                int g = functionG(w[i - 1], (i / 2) - 1);
//                w[i] = w[i - 2] ^ g;
//            } else {
//                w[i] = w[i - 1] ^ w[i - 2];
//            }
//        }
//        return w;
//    }
//
//    private static int functionG(int byteVal, int rconIndex) {
//        int rotated = leftRotate(byteVal);
//        int substituted = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 0x0F];
//        return substituted ^ RCON[rconIndex];
//    }
//
//    private static int leftRotate(int byteVal) {
//        return ((byteVal & 0x0F) << 4) | ((byteVal & 0xF0) >> 4);
//    }
//
//    private static int addRoundKey(int state, int key1, int key2) {
//        int combinedKey = ((key1 << 8) | key2) & 0xFFFF;
//        return state ^ combinedKey;
//    }
//
//    private static int nibbleSub(int input) {
//        int result = 0;
//        for (int i = 0; i < 16; i += 4) {
//            int nibble = (input >> i) & 0xF;
//            int substituted = SBOX[nibble];
//            result |= (substituted << i);
//        }
//        return result & 0xFFFF;
//    }
//
//    private static int invNibbleSub(int input) {
//        int result = 0;
//        for (int i = 0; i < 16; i += 4) {
//            int nibble = (input >> i) & 0xF;
//            int substituted = INV_SBOX[nibble];
//            result |= (substituted << i);
//        }
//        return result & 0xFFFF;
//    }
//
//    private static int shiftRows(int input) {
//        int highByte = (input & 0xFF00);
//        int lowByte = input & 0xFF;
//        int shiftedLowByte = ((lowByte & 0x0F) << 4) | ((lowByte & 0xF0) >> 4);
//        return (highByte | shiftedLowByte) & 0xFFFF;
//    }
//
//    private static int invShiftRows(int input) {
//        return shiftRows(input) & 0xFFFF;
//    }
//
//    private static int mixColumns(int input) {
//        int[] colMatrix = {1, 4, 4, 1};
//
//        int upperHalf = input >> 8;
//        int lowerHalf = input & 0xFF;
//
//        int a = upperHalf >> 4;
//        int b = upperHalf & 0xF;
//        int c = lowerHalf >> 4;
//        int d = lowerHalf & 0xF;
//
//        int newA = gfAdd(gfMultiply(colMatrix[0], a), gfMultiply(colMatrix[1], b));
//        int newB = gfAdd(gfMultiply(colMatrix[2], a), gfMultiply(colMatrix[3], b));
//        int newC = gfAdd(gfMultiply(colMatrix[0], c), gfMultiply(colMatrix[1], d));
//        int newD = gfAdd(gfMultiply(colMatrix[2], c), gfMultiply(colMatrix[3], d));
//
//        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
//    }
//
//    private static int invMixColumns(int input) {
//        int[] invColMatrix = {9, 2, 2, 9};
//
//        int upperHalf = input >> 8;
//        int lowerHalf = input & 0xFF;
//
//        int a = upperHalf >> 4;
//        int b = upperHalf & 0xF;
//        int c = lowerHalf >> 4;
//        int d = lowerHalf & 0xF;
//
//        int newA = gfAdd(gfMultiply(invColMatrix[0], a), gfMultiply(invColMatrix[1], b));
//        int newB = gfAdd(gfMultiply(invColMatrix[2], a), gfMultiply(invColMatrix[3], b));
//        int newC = gfAdd(gfMultiply(invColMatrix[0], c), gfMultiply(invColMatrix[1], d));
//        int newD = gfAdd(gfMultiply(invColMatrix[2], c), gfMultiply(invColMatrix[3], d));
//
//        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
//    }
//
//    private static int gfAdd(int a, int b) {
//        return a ^ b;
//    }
//
//    private static int gfMultiply(int a, int b) {
//        int result = 0;
//        while (b != 0) {
//            if ((b & 1) != 0) {
//                result ^= a;
//            }
//            b >>= 1;
//            a <<= 1;
//            if ((a & 0x10) != 0) {
//                a ^= 0b10011;
//            }
//        }
//        return result & 0xF;
//    }
//}
import java.util.HashMap;
import java.util.Map;

public class SAESCore {

    // S-box 表
    private static final int[] SBOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
    private static final int[] INV_SBOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};
    private static final int[] RCON = {0x80, 0x30};

    public static void main(String[] args) {
        String key = "1010101010101010"; // 16位二进制密钥
        String plaintext = "1010101010101010"; // 16位二进制明文

        // 基本加密解密测试
        String ciphertext = encryptBinary(plaintext, key);
        System.out.println("密文: " + ciphertext);

        String decryptedText = decryptBinary(ciphertext, key);
        System.out.println("解密文本: " + decryptedText);

        if (plaintext.equals(decryptedText)) {
            System.out.println("测试通过: 加密和解密一致。");
        } else {
            System.out.println("测试失败: 解密文本与原始明文不匹配。");
        }

        // 双重加密和解密
        String key1 = "1110011101111101";
        String key2 = "0000000000000000";
        String doubleEncrypted = doubleEncrypt(plaintext, key1, key2);
        System.out.println("双重加密: " + doubleEncrypted);
        String doubleDecrypted = doubleDecrypt(doubleEncrypted, key1, key2);
        System.out.println("双重解密: " + doubleDecrypted);

        // 三重加密 (32位模式)
        String tripleEncrypted32 = tripleEncrypt32(plaintext, key1, key2);
        System.out.println("三重加密 (32位模式): " + tripleEncrypted32);
        String tripleDecrypted32 = tripleDecrypt32(tripleEncrypted32, key1, key2);
        System.out.println("三重解密 (32位模式): " + tripleDecrypted32);

        // 三重加密 (48位模式)
        String key3 = "0000111100001111";
        String tripleEncrypted48 = tripleEncrypt48(plaintext, key1, key2, key3);
        System.out.println("三重加密 (48位模式): " + tripleEncrypted48);
        String tripleDecrypted48 = tripleDecrypt48(tripleEncrypted48, key1, key2, key3);
        System.out.println("三重解密 (48位模式): " + tripleDecrypted48);

        // CBC模式加密和篡改测试
        String iv = "0000111100001111";
        String cbcEncrypted = cbcEncrypt(plaintext, key1, iv);
        System.out.println("CBC加密: " + cbcEncrypted);
        String cbcDecrypted = cbcDecrypt(cbcEncrypted, key1, iv);
        System.out.println("CBC解密: " + cbcDecrypted);

        // 篡改后的密文解密
        String tamperedCiphertext = cbcEncrypted.substring(0, cbcEncrypted.length() - 4) + "1010"; // 人为篡改
        System.out.println("篡改后的密文: " + tamperedCiphertext);
        String tamperedDecrypted = cbcDecrypt(tamperedCiphertext, key1, iv);
        System.out.println("篡改解密: " + tamperedDecrypted);

        String result = meetInTheMiddleAttack(plaintext, doubleEncrypted);
        System.out.println(result);
    }


    // 双重加密
    public static String doubleEncrypt(String plaintext, String key1, String key2) {
        String firstEncryption = encryptBinary(plaintext, key1);
        return encryptBinary(firstEncryption, key2);
    }

    // 双重解密
    public static String doubleDecrypt(String ciphertext, String key1, String key2) {
        String firstDecryption = decryptBinary(ciphertext, key2);
        return decryptBinary(firstDecryption, key1);
    }

    // 三重加密 (32-bit模式)
    public static String tripleEncrypt32(String plaintext, String key1, String key2) {
        String firstEncrypt = encryptBinary(plaintext, key1);
        String secondDecrypt = decryptBinary(firstEncrypt, key2);
        return encryptBinary(secondDecrypt, key1);
    }

    // 三重解密 (32-bit模式)
    public static String tripleDecrypt32(String ciphertext, String key1, String key2) {
        String firstDecrypt = decryptBinary(ciphertext, key1);
        String secondEncrypt = encryptBinary(firstDecrypt, key2);
        return decryptBinary(secondEncrypt, key1);
    }

    // 三重加密 (48-bit模式)
    public static String tripleEncrypt48(String plaintext, String key1, String key2, String key3) {
        String firstEncrypt = encryptBinary(plaintext, key1);
        String secondDecrypt = decryptBinary(firstEncrypt, key2);
        return encryptBinary(secondDecrypt, key3);
    }

    // 三重解密 (48-bit模式)
    public static String tripleDecrypt48(String ciphertext, String key1, String key2, String key3) {
        String firstDecrypt = decryptBinary(ciphertext, key3);
        String secondEncrypt = encryptBinary(firstDecrypt, key2);
        return decryptBinary(secondEncrypt, key1);
    }

    // CBC模式加密
    public static String cbcEncrypt(String plaintext, String key, String iv) {
        String xorWithIv = xor(plaintext, iv);
        return encryptBinary(xorWithIv, key);
    }

    // CBC模式解密
    public static String cbcDecrypt(String ciphertext, String key, String iv) {
        String decryptedBlock = decryptBinary(ciphertext, key);
        return xor(decryptedBlock, iv);
    }

    // 工具方法：XOR操作
    private static String xor(String input1, String input2) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input1.length(); i++) {
            result.append(input1.charAt(i) == input2.charAt(i) ? '0' : '1');
        }
        return result.toString();
    }

    // S-AES核心加密
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

    // S-AES核心解密
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

    // 密钥扩展
    private static int[] keyExpansion(int key) {
        int[] w = new int[6];
        w[0] = (key >> 8) & 0xFF;
        w[1] = key & 0xFF;

        for (int i = 2; i < 6; i++) {
            if (i % 2 == 0) {
                int g = functionG(w[i - 1], (i / 2) - 1);
                w[i] = w[i - 2] ^ g;
            } else {
                w[i] = w[i - 1] ^ w[i - 2];
            }
        }
        return w;
    }

    private static int functionG(int byteVal, int rconIndex) {
        int rotated = leftRotate(byteVal);
        int substituted = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 0x0F];
        return substituted ^ RCON[rconIndex];
    }

    private static int leftRotate(int byteVal) {
        return ((byteVal & 0x0F) << 4) | ((byteVal & 0xF0) >> 4);
    }

    private static int addRoundKey(int state, int key1, int key2) {
        int combinedKey = ((key1 << 8) | key2) & 0xFFFF;
        return state ^ combinedKey;
    }

    private static int nibbleSub(int input) {
        int result = 0;
        for (int i = 0; i < 16; i += 4) {
            int nibble = (input >> i) & 0xF;
            int substituted = SBOX[nibble];
            result |= (substituted << i);
        }
        return result & 0xFFFF;
    }

    private static int invNibbleSub(int input) {
        int result = 0;
        for (int i = 0; i < 16; i += 4) {
            int nibble = (input >> i) & 0xF;
            int substituted = INV_SBOX[nibble];
            result |= (substituted << i);
        }
        return result & 0xFFFF;
    }

    private static int shiftRows(int input) {
        int highByte = (input & 0xFF00);
        int lowByte = input & 0xFF;
        int shiftedLowByte = ((lowByte & 0x0F) << 4) | ((lowByte & 0xF0) >> 4);
        return (highByte | shiftedLowByte) & 0xFFFF;
    }

    private static int invShiftRows(int input) {
        return shiftRows(input) & 0xFFFF;
    }

    private static int mixColumns(int input) {
        int[] colMatrix = {1, 4, 4, 1};

        int upperHalf = input >> 8;
        int lowerHalf = input & 0xFF;

        int a = upperHalf >> 4;
        int b = upperHalf & 0xF;
        int c = lowerHalf >> 4;
        int d = lowerHalf & 0xF;

        int newA = gfAdd(gfMultiply(colMatrix[0], a), gfMultiply(colMatrix[1], b));
        int newB = gfAdd(gfMultiply(colMatrix[2], a), gfMultiply(colMatrix[3], b));
        int newC = gfAdd(gfMultiply(colMatrix[0], c), gfMultiply(colMatrix[1], d));
        int newD = gfAdd(gfMultiply(colMatrix[2], c), gfMultiply(colMatrix[3], d));

        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
    }

    private static int invMixColumns(int input) {
        int[] invColMatrix = {9, 2, 2, 9};

        int upperHalf = input >> 8;
        int lowerHalf = input & 0xFF;

        int a = upperHalf >> 4;
        int b = upperHalf & 0xF;
        int c = lowerHalf >> 4;
        int d = lowerHalf & 0xF;

        int newA = gfAdd(gfMultiply(invColMatrix[0], a), gfMultiply(invColMatrix[1], b));
        int newB = gfAdd(gfMultiply(invColMatrix[2], a), gfMultiply(invColMatrix[3], b));
        int newC = gfAdd(gfMultiply(invColMatrix[0], c), gfMultiply(invColMatrix[1], d));
        int newD = gfAdd(gfMultiply(invColMatrix[2], c), gfMultiply(invColMatrix[3], d));

        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
    }

    private static int gfAdd(int a, int b) {
        return a ^ b;
    }

    private static int gfMultiply(int a, int b) {
        int result = 0;
        while (b != 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            b >>= 1;
            a <<= 1;
            if ((a & 0x10) != 0) {
                a ^= 0b10011;
            }
        }
        return result & 0xF;
    }
    public static String meetInTheMiddleAttack(String plaintext, String ciphertext) {
        // 我们假设K1和K2都是16位的密钥（也就是范围从0到65535）
        Map<String, Integer> encryptionMap = new HashMap<>();

        // 计算所有可能的E(K1, P)，并将其存入map，键是E(K1, P)，值是对应的K1
        for (int key1 = 0; key1 < 65536; key1++) {
            String key1Binary = String.format("%16s", Integer.toBinaryString(key1)).replace(' ', '0');
            String encrypted = encryptBinary(plaintext, key1Binary);
            encryptionMap.put(encrypted, key1);  // 存储中间加密结果和对应的K1
        }

        // 计算所有可能的D(K2, C)，并在encryptionMap中寻找匹配项
        for (int key2 = 0; key2 < 65536; key2++) {
            String key2Binary = String.format("%16s", Integer.toBinaryString(key2)).replace(' ', '0');
            String decrypted = decryptBinary(ciphertext, key2Binary);

            if (encryptionMap.containsKey(decrypted)) {
                // 找到匹配的中间值，返回对应的K1和K2
                int matchingKey1 = encryptionMap.get(decrypted);
                System.out.println("Meet-in-the-Middle Attack Success!");
                System.out.println("K1: " + String.format("%16s", Integer.toBinaryString(matchingKey1)).replace(' ', '0'));
                System.out.println("K2: " + key2Binary);
                return "Found Keys: K1 = " + String.format("%16s", Integer.toBinaryString(matchingKey1)).replace(' ', '0') + ", K2 = " + key2Binary;
            }
        }

        return "No matching keys found!";
    }
}
