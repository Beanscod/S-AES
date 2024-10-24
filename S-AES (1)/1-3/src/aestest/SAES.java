package aestest;
import aestest.SAES;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;

public class SAES extends JFrame {

    private JTextField binaryInputField;
    private JTextField asciiInputField;
    private JTextField keyField;
    private JTextField ciphertextField;

    // S-box 表
    private static final int[] SBOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
    private static final int[] INV_SBOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};
    // 轮常数 RCON
    private static final int[] RCON = {0x80, 0x30};  // 仅考虑到了两轮的情况
    public SAES() {
        setTitle("S-AES 加密与解密 (支持 ASCII 和二进制)");
        setSize(500, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(5, 2));

        // GUI 组件初始化
        JLabel binaryLabel = new JLabel("二进制输入 (16-bit):");
        binaryInputField = new JTextField();

        JLabel asciiLabel = new JLabel("ASCII 输入:");
        asciiInputField = new JTextField();

        JLabel keyLabel = new JLabel("输入密钥 (16-bit 二进制):");
        keyField = new JTextField();

        JLabel ciphertextLabel = new JLabel("输出:");
        ciphertextField = new JTextField();
        ciphertextField.setEditable(false);

        JButton encryptButton = new JButton("加密");
        JButton decryptButton = new JButton("解密");

        // 加密按钮事件
        encryptButton.addActionListener(new EncryptListener());
        // 解密按钮事件
        decryptButton.addActionListener(new DecryptListener());

        // 添加组件到窗口
        add(binaryLabel);
        add(binaryInputField);
        add(asciiLabel);
        add(asciiInputField);
        add(keyLabel);
        add(keyField);
        add(ciphertextLabel);
        add(ciphertextField);
        add(encryptButton);
        add(decryptButton);

        setVisible(true);
    }

    // 加密按钮监听器
    private class EncryptListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String binaryInput = binaryInputField.getText();
            String asciiInput = asciiInputField.getText();
            String key = keyField.getText();

            if (!binaryInput.isEmpty()) {
                // 如果输入了二进制字符串，则按二进制加密
                String ciphertext = encryptBinary(binaryInput, key);
                ciphertextField.setText(ciphertext);
            } else if (!asciiInput.isEmpty()) {
                // 如果输入了 ASCII 字符串，则按 ASCII 加密
                String ciphertext = encryptASCII(asciiInput, key);
                ciphertextField.setText(ciphertext);
            } else {
                JOptionPane.showMessageDialog(null, "请输入二进制或 ASCII 字符串！");
            }
        }
    }

    // 解密按钮监听器
    private class DecryptListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            String binaryInput = binaryInputField.getText();
            String key = keyField.getText();

            if (!binaryInput.isEmpty()) {
                // 仅支持二进制解密
                String decryptedText = decryptBinary(binaryInput, key);
                ciphertextField.setText(decryptedText);
            } else {
                JOptionPane.showMessageDialog(null, "只能解密二进制输入！");
            }
        }
    }
    private void printRoundKeys(int[] keys) {
        for (int i = 0; i < keys.length; i++) {
            System.out.println("w[" + i + "]: " + Integer.toHexString(keys[i]));
        }
    }

    private static int[] keyExpansion(int key) {
        int[] w = new int[6];
        w[0] = (key >> 8) & 0xFF;  // High 8 bits of the key
        w[1] = key & 0xFF;         // Low 8 bits of the key

        for (int i = 2; i < 6; i++) {
            if (i % 2 == 0) {
                // Process using function g on w[i-1] (right part of the previous key)
                int g = functionG(w[i-1], (i / 2) - 1);
                w[i] = w[i - 2] ^ g;
            } else {
                w[i] = w[i - 1] ^ w[i - 2];
            }
        }
        return w;
    }

    private static int functionG(int byteVal, int rconIndex) {
        // Left rotate the byte
        int rotated = leftRotate(byteVal);
        // Apply S-box substitution on both nibbles
        int substituted = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 0x0F];
        // XOR with the round constant
        return substituted ^ RCON[rconIndex];
    }

    private static int leftRotate(int byteVal) {
        // Swap nibbles
        return ((byteVal & 0x0F) << 4) | ((byteVal & 0xF0) >> 4);
    }


    // 二进制字符串加密
    private String encryptBinary(String plaintext, String key) {
        int pt = Integer.parseInt(plaintext, 2);
        System.out.println("Initial plaintext: " + Integer.toBinaryString(pt));
        int k = Integer.parseInt(key, 2);

        int[] w = keyExpansion(k);
        printRoundKeys(w);  // 调试密钥
        //第一次轮密钥加
        int state = addRoundKey(pt, w[0], w[1]);
        String output = String.format("%16s", Integer.toBinaryString(state & 0xFFFF)).replace(' ', '0');
        System.out.println(output);

        state = nibbleSub(state);
        System.out.println("After nibbleSub: " + Integer.toBinaryString(state));
        state = shiftRows(state);
        System.out.println("After shiftRows: " + Integer.toBinaryString(state));
        state = mixColumns(state);
        String output2 = String.format("%16s", Integer.toBinaryString(state & 0xFFFF)).replace(' ', '0');
        System.out.println(output2);


        state = addRoundKey(state, w[2], w[3]);
        System.out.println("After second addRoundKey: " + Integer.toBinaryString(state));
        state = nibbleSub(state);
        System.out.println("After second nibbleSub: " + Integer.toBinaryString(state));
        state = shiftRows(state);
        System.out.println("After second shiftRows: " + Integer.toBinaryString(state));

        int ciphertext = addRoundKey(state, w[4], w[5]);
        System.out.println("Final ciphertext: " + Integer.toBinaryString(ciphertext));

        return String.format("%16s", Integer.toBinaryString(ciphertext)).replace(' ', '0');
    }


    // 轮密钥加 (AddRoundKey)
    private int addRoundKey(int state, int key1, int key2) {
        int combinedKey = ((key1 << 8) | key2) & 0xFFFF;  // 确保combinedKey是16位
        int result = state ^ combinedKey;
        return result & 0xFFFF;  // 确保输出为16位
    }


    // ASCII 字符串加密
    private String encryptASCII(String plaintext, String key) {
        StringBuilder encryptedResult = new StringBuilder();
        byte[] bytes = plaintext.getBytes(StandardCharsets.US_ASCII);

        // 按 2 字节为一组处理
        for (int i = 0; i < bytes.length; i += 2) {
            // 获取当前 2 字节，并将其组成 16-bit 二进制块
            int block = (bytes[i] << 8) | (i + 1 < bytes.length ? bytes[i + 1] : 0);

            // 将该块转换为二进制字符串，并加密
            String encryptedBinary = encryptBinary(Integer.toBinaryString(block), key);

            // 将加密后的二进制块转换为整数
            int encryptedBlock = Integer.parseInt(encryptedBinary, 2);

            // 将整数形式的加密块转换为 4 个 ASCII 字符并添加到结果
            encryptedResult.append((char) ((encryptedBlock >> 8) & 0xFF)); // 高位字符
            encryptedResult.append((char) (encryptedBlock & 0xFF));        // 低位字符
        }

        return encryptedResult.toString();
    }

    // 二进制字符串解密
    private String decryptBinary(String ciphertext, String key) {
        int ct = Integer.parseInt(ciphertext, 2);
        int k = Integer.parseInt(key, 2);

        int[] w = keyExpansion(k);
        printRoundKeys(w);  // 调试密钥

        int state = addRoundKey(ct, w[4], w[5]);
        System.out.println("After addRoundKey: " + Integer.toBinaryString(state));
        state = invShiftRows(state);
        System.out.println("After invShiftRows: " + Integer.toBinaryString(state));
        state = invNibbleSub(state);
        System.out.println("After invNibbleSub: " + Integer.toBinaryString(state));
        state = addRoundKey(state, w[2], w[3]);

        state = invMixColumns(state);
        state = invShiftRows(state);
        state = invNibbleSub(state);
        int plaintext = addRoundKey(state, w[0], w[1]);

        return String.format("%16s", Integer.toBinaryString(plaintext)).replace(' ', '0');
    }




    private int nibbleSub(int input) {
        int result = 0;
        for (int i = 0; i < 16; i += 4) {
            int nibble = (input >> i) & 0xF;  // 提取每个4位半字节
            int substituted = SBOX[nibble];   // 使用S-Box替换
            result |= (substituted << i);     // 将替换后的半字节放回原来的位置
        }
        return result & 0xFFFF;  // 确保输出为16位
    }
    // 逆半字节代替 (Inverse Nibble Substitution)
    private int invNibbleSub(int input) {
        int result = 0;
        for (int i = 0; i < 16; i += 4) {
            int nibble = (input >> i) & 0xF;  // 提取每个4位半字节
            int substituted = INV_SBOX[nibble];   // 使用逆 S-Box 替换
            result |= (substituted << i);     // 将替换后的半字节放回原来的位置
        }
        return result & 0xFFFF;  // 确保输出为16位
    }


    private int formatNibble(int nibble) {
        return nibble & 0xF;  // 确保半字节是4位，这里不需要更改
    }

    private int shiftRows(int input) {
        // 高8位不变
        int highByte = (input & 0xFF00);
        // 低8位分为两个半字节
        int lowByte = input & 0xFF;
        // 执行半字节移位：低4位移到高4位位置，高4位移到低4位位置
        int shiftedLowByte = ((lowByte & 0x0F) << 4) | ((lowByte & 0xF0) >> 4);
        // 组合回16位整数
        return (highByte | shiftedLowByte) & 0xFFFF;  // 确保输出为16位
    }
    private int invShiftRows(int input) {
        return shiftRows(input) & 0xFFFF;  // 如果只有两个元素，左循环移位的逆操作也是自身，并确保结果为16位
    }
    private int gfAdd(int a, int b) {
        return (a ^ b) & 0xF;  // GF(2^4)加法就是异或，保证输出为4位
    }

    private int gfMultiply(int a, int b) {
        int result = 0;
        while (b != 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            b >>= 1;
            a <<= 1;
            if ((a & 0x10) != 0) {  // 检查是否超过4位
                a ^= 0b10011;  // 应用约减多项式x^4 + x + 1
            }
        }
        return result & 0xF;  // 保证结果是4位
    }

    private int mixColumns(int input) {
        // 假设的列混淆矩阵，更正为可能的正确使用
        int[] colMatrix = {1, 4, 4, 1};

        // 假设 input 是完整的16位，需要分解为更多部分或正确理解
        int upperHalf = input >> 8;  // 输入的上半字节
        int lowerHalf = input & 0xFF;  // 输入的下半字节

        int a = upperHalf >> 4;  // 上半字节的高4位
        int b = upperHalf & 0xF;  // 上半字节的低4位
        int c = lowerHalf >> 4;  // 下半字节的高4位
        int d = lowerHalf & 0xF;  // 下半字节的低4位

        // 根据列混淆矩阵计算新的半字节值
        int newA = gfAdd(gfMultiply(colMatrix[0], a), gfMultiply(colMatrix[1], b));
        int newB = gfAdd(gfMultiply(colMatrix[2], a), gfMultiply(colMatrix[3], b));
        int newC = gfAdd(gfMultiply(colMatrix[0], c), gfMultiply(colMatrix[1], d));
        int newD = gfAdd(gfMultiply(colMatrix[2], c), gfMultiply(colMatrix[3], d));

        // 将计算后的半字节重新组合成一个16位的整数
        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
    }


    private int invMixColumns(int input) {
        int[] invColMatrix = {9, 2, 2, 9};  // 假设的逆列混淆矩阵，这需要根据实际矩阵计算得出


        // 假设 input 是完整的16位，需要分解为更多部分或正确理解
        int upperHalf = input >> 8;  // 输入的上半字节
        int lowerHalf = input & 0xFF;  // 输入的下半字节

        int a = upperHalf >> 4;  // 上半字节的高4位
        int b = upperHalf & 0xF;  // 上半字节的低4位
        int c = lowerHalf >> 4;  // 下半字节的高4位
        int d = lowerHalf & 0xF;  // 下半字节的低4位

        // 根据列混淆矩阵计算新的半字节值
        int newA = gfAdd(gfMultiply(invColMatrix[0], a), gfMultiply(invColMatrix[1], b));
        int newB = gfAdd(gfMultiply(invColMatrix[2], a), gfMultiply(invColMatrix[3], b));
        int newC = gfAdd(gfMultiply(invColMatrix[0], c), gfMultiply(invColMatrix[1], d));
        int newD = gfAdd(gfMultiply(invColMatrix[2], c), gfMultiply(invColMatrix[3], d));

        // 将计算后的半字节重新组合成一个16位的整数
        return ((newA << 12) | (newB << 8) | (newC << 4) | newD) & 0xFFFF;
    }


    private void testEncryptionDecryption() {
        String key = "0010110101010101"; // 16-bit binary key
        String plaintext = "1010011101001001"; // 16-bit binary plaintext
        String ciphertext = encryptBinary(plaintext, key);
        String decryptedText = decryptBinary(ciphertext, key);

        System.out.println("Original Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted Text: " + decryptedText);

        if (plaintext.equals(decryptedText)) {
            System.out.println("Test Passed: Encryption and decryption are consistent.");
        } else {
            System.out.println("Test Failed: Decrypted text does not match the original plaintext.");
        }
    }

    private boolean testSBoxAndInvSBox() {
        for (int i = 0; i < 16; i++) {
            if (INV_SBOX[SBOX[i]] != i) {
                System.out.println("Error: S-Box and Inverse S-Box do not match at index " + i);
                return false;
            }
        }
        return true;
    }
    private void testMixColumnsAndInvMixColumns() {
        int testInput = 0xAB;  // 测试输入
        System.out.println("Testing MixColumns and InvMixColumns:");
        System.out.println("Original Input: " + Integer.toHexString(testInput));

        int mixed = mixColumns(testInput);
        System.out.println("After MixColumns: " + Integer.toHexString(mixed));

        int unmixed = invMixColumns(mixed);
        System.out.println("After InvMixColumns: " + Integer.toHexString(unmixed));

        if (testInput == unmixed) {
            System.out.println("Test Passed: The input matches the unmixed output.");
        } else {
            System.out.println("Test Failed: The unmixed output does not match the original input.");
        }
    }


    public static void main(String[] args) {
        //SAES saes =
                new SAES();
//        if (saes.testSBoxAndInvSBox()) {
//            System.out.println("S-Box and Inverse S-Box test passed.");
//        } else {
//            System.out.println("S-Box and Inverse S-Box test failed.");
//        }
        //saes.testEncryptionDecryption();
//saes.testMixColumnsAndInvMixColumns();
    }

}
