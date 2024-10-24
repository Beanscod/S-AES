package aestest;
import aestest.SAES;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;

public class test extends JFrame {

    private JTextField binaryInputField;
    private JTextField asciiInputField;
    private JTextField keyField;
    private JTextField ciphertextField;

    // S-box 表
    private static final int[] SBOX = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
    private static final int[] INV_SBOX = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

    public test() {
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

        JLabel ciphertextLabel = new JLabel("密文 (ASCII):");
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
    // 扩展密钥，生成 6 个 8-bit 轮密钥 w[0] 到 w[5]
    private int[] keyExpansion(int key) {
        int[] w = new int[6];
        // w[0] 和 w[1] 是密钥的前 8 位和后 8 位
        w[0] = (key >> 8) & 0xFF;
        w[1] = key & 0xFF;

        // 扩展 w[2] 到 w[5]
        for (int i = 2; i < 6; i++) {
            if (i % 2 == 0) {
                w[i] = w[i - 2] ^ (0x80 >> (i / 2 - 1)); // 简化的轮常量 RCON
            } else {
                w[i] = w[i - 1] ^ w[i - 2];
            }
        }
        return w;
    }

    // 二进制字符串加密
    private String encryptBinary(String plaintext, String key) {
        int pt = Integer.parseInt(plaintext, 2);
        int k = Integer.parseInt(key, 2);

        // 扩展密钥
        int[] w = keyExpansion(k);

        // 第一轮：轮密钥加、半字节代替、行移位、列混淆
        int state = addRoundKey(pt, w[0], w[1]);
        state = nibbleSub(state);
        state = shiftRows(state);
        state = mixColumns(state);

        // 第二轮：轮密钥加、半字节代替、行移位
        state = addRoundKey(state, w[2], w[3]);
        state = nibbleSub(state);
        state = shiftRows(state);

        // 最后一轮：轮密钥加
        int ciphertext = addRoundKey(state, w[4], w[5]);

        // 返回加密后的 16-bit 二进制字符串
        return String.format("%16s", Integer.toBinaryString(ciphertext)).replace(' ', '0');
    }

    // 轮密钥加 (AddRoundKey)
    private int addRoundKey(int state, int key1, int key2) {
        return state ^ ((key1 << 8) | key2);
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

        // 扩展密钥
        int[] w = keyExpansion(k);

        // 最后一轮：轮密钥加
        int state = addRoundKey(ct, w[4], w[5]);

        // 第二轮：逆行移位、逆半字节代替、轮密钥加
        state = invShiftRows(state);
        state = invNibbleSub(state);
        state = addRoundKey(state, w[2], w[3]);

        // 第一轮：逆列混淆、逆行移位、逆半字节代替、轮密钥加
        state = invMixColumns(state);
        state = invShiftRows(state);
        state = invNibbleSub(state);
        int plaintext = addRoundKey(state, w[0], w[1]);

        // 返回解密后的 16-bit 二进制字符串
        return String.format("%16s", Integer.toBinaryString(plaintext)).replace(' ', '0');
    }
    // 半字节代替 (Nibble Substitution)
    private int nibbleSub(int input) {
        // 使用位掩码确保输入的每个半字节都在 0-15 之间
        int highNibble = (input >> 4) & 0xF;  // 提取高 4 位
        int lowNibble = input & 0xF;          // 提取低 4 位

        // 使用 S-box 替换高低半字节
        return (SBOX[highNibble] << 4) | SBOX[lowNibble];
    }

    // 逆半字节代替 (Inverse Nibble Substitution)
    private int invNibbleSub(int input) {
        // 使用位掩码确保输入的每个半字节都在 0-15 之间
        int highNibble = (input >> 4) & 0xF;  // 提取高 4 位
        int lowNibble = input & 0xF;          // 提取低 4 位

        // 使用逆 S-box 替换高低半字节
        return (INV_SBOX[highNibble] << 4) | INV_SBOX[lowNibble];
    }


    private int shiftRows(int input) {
        return ((input & 0xF0) >> 4) | ((input & 0x0F) << 4);
    }

    private int invShiftRows(int input) {
        return shiftRows(input);  // 对称操作
    }

    private int mixColumns(int input) {
        int a = input >> 4;
        int b = input & 0xF;
        return ((a ^ b) << 4) | a;
    }

    private int invMixColumns(int input) {
        int a = input >> 4;
        int b = input & 0xF;
        return ((a ^ b) << 4) | b;
    }


    public static void main(String[] args) {
        new test();
    }
}
