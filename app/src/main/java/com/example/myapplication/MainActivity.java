package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "lai_test";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.helloworld).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    RSA rsa = new RSA();
                    rsa.generate(1024);
//                    Log.d(TAG, rsa.getPublicKey());
//                    Log.d(TAG, rsa.getPrivateKey());

                    String phonePublicKey = Base64.encodeToString(rsa.getPublicKey2().getEncoded(), Base64.DEFAULT);
                    //send phonePublicKey to hmd
                    String serial = "1234567890";
                    byte[] encrypted = getEncryptedSerial(serial, phonePublicKey);
                    Log.d(TAG, "encrypted:" + printHex(encrypted));

                    //send back to phone
                    String encryptedBase64 = Base64.encodeToString(encrypted, Base64.DEFAULT);
                    String decryped = rsa.decrypt64(encryptedBase64);
                    Log.d(TAG, "decryped from RSA:" + decodeBase64(decryped));


                    //encrypt from phone
                    encrypted = rsa.encrypt(serial.getBytes());
                    //send back to phone
                    decryped = decryptSerial(encrypted, rsa.getPrivateKey2());
                    Log.d(TAG, "decryped from RSAUtil:" + decryped);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        findViewById(R.id.test2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String publicAccount = "1234567890";
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashAccount = digest.digest(publicAccount.getBytes());
                    Log.d(TAG, "hash account=" + hashAccount.length); //32 bytes
                    Log.d(TAG, bytesToHex(hashAccount));

                    byte[] randomSeed = intToByteArray((int) System.currentTimeMillis() / 1000);

                    Log.d(TAG, "randomSeed=" + hashAccount.length); //4 bytes
                    Log.d(TAG, bytesToHex(randomSeed));

                    byte[] combined = new byte[hashAccount.length + randomSeed.length];

                    for (int i = 0; i < combined.length; ++i) {
                        combined[i] = i < hashAccount.length ? hashAccount[i] : randomSeed[i - hashAccount.length];
                    }
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        });

    }

    public static byte[] intToByteArray(int a)
    {
        byte[] ret = new byte[4];
        ret[3] = (byte) (a & 0xFF);
        ret[2] = (byte) ((a >> 8) & 0xFF);
        ret[1] = (byte) ((a >> 16) & 0xFF);
        ret[0] = (byte) ((a >> 24) & 0xFF);
        return ret;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
        if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private String decodeBase64(String coded){
        byte[] valueDecoded= new byte[0];
        valueDecoded = Base64.decode(coded.getBytes(), Base64.DEFAULT);
        return new String(valueDecoded);
    }

    private byte[] getEncryptedSerial(String serial, String phonePublicKey) {
        try {
            RSAUtil rsaUtil = new RSAUtil(phonePublicKey, null);
            return rsaUtil.encrypt(serial.getBytes());
        } catch (Exception e) {
            Log.i(TAG, "encrypt serial fail:" + e.toString());
            return null;
        }
    }

    private String decryptSerial(byte[] encrytedSerial, PrivateKey privateKey) {
        try {
            Context context = MainActivity.this;
            RSAUtil rsaUtil = new RSAUtil(null, privateKey);
            byte[] serialBytes = rsaUtil.decrypt(encrytedSerial);
            return new String(serialBytes);
        } catch (Exception e) {
            Log.e(TAG, "decryptSerial fail:" + e.toString());
            return null;
        }
    }


    final static char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String printHex(byte[] array) {
        return printHex(array, 0, array.length);
    }

    public static String printHex(byte[] array, int offset, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            byte b = array[offset + i];
            if (sb.length() > 0)
                sb.append(' ');
            sb.append(digits[b >> 4 & 0x0F]);
            sb.append(digits[b & 0x0F]);
        }
        return sb.toString();
    }
}
