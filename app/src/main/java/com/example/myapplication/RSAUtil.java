package com.example.myapplication;

import android.util.Base64;
import android.util.Log;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSAUtil {

    final static String TAG = "RSAUtil";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAUtil(String publicKeyString, String privateKeyString) {
        publicKey = generatePublicKey(publicKeyString);
        privateKey = generatePrivateKey(privateKeyString);
    }

    public RSAUtil(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    private static PublicKey generatePublicKey(String publicKeyString) {
        try {
            X509EncodedKeySpec data = new X509EncodedKeySpec(Base64.decode(publicKeyString.getBytes(), Base64.DEFAULT));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(data);
            return publicKey;
        } catch (Exception e) {
            Log.e(TAG, "generatePublicKey fail:" + e.toString());
            return null;
        }
    }

    private static PrivateKey generatePrivateKey(String privateKeyString) {
        try {
            PKCS8EncodedKeySpec data = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString.getBytes(), Base64.DEFAULT));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(data);
            return privateKey;
        } catch (Exception e) {
            Log.e(TAG, "generatePrivateKey fail:" + e.toString());
            return null;
        }
    }

    public byte[] encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptData = cipher.doFinal(data);
            return encryptData;
        } catch (Exception e) {
            Log.e(TAG, "encrypt fail:" + e.toString());
            return null;
        }
    }

    public byte[] decrypt(byte[] encryptData) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptData = cipher.doFinal(encryptData);
            return decryptData;
        } catch (Exception e) {
            Log.e(TAG, "decrypt fail:" + e.toString());
            return null;
        }
    }
}
