import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class LicenseManager {
  private PrivateKey privateKey;

  // constants
  public static final String SIGN_ALGORITHM = "SHA256WithRSA";
  public static final String RSA_ALGORITHM = "RSA";
  public static final String PRIVATE_KEY_PATH = "private.key";

  /**
   * Initialize the license manager and read the private key
   */
  public LicenseManager() {
    System.out.println("LicenseManager service started...");
    privateKey = getPrivateKey();
  }

  /**
   * Start the license manager process with given md5 hash and RSA encrypted
   * cipher text
   * 
   * @param hash
   * @param cipherText
   */
  public void start(String hash, String cipherText) {
    System.out.println("Server -- Server is being requested...");
    System.out.println("Server -- Incoming Encrypted Text: " + cipherText);

    decryptLicense(cipherText);
    String localHash = createHash(cipherText);

    if (!hash.equals(localHash)) {
      System.out.println("Error:: Data is corrupted, exiting...");
      System.exit(1);
    }

    String signature = signLicense(localHash);
    Client.saveLicense(signature);
  }

  /**
   * Create md5 hash of given string
   * 
   * @param cipherText
   * @return md5 hash
   */
  private static String createHash(String cipherText) {
    String hash = createMD5Hash(cipherText);
    System.out.println("Server -- MD5 Plain License Text: " + hash);
    return hash;
  }

  /**
   * Decrypt the license using RSA with private key
   * 
   * @param cipherText
   * @return decrypted license
   */
  private String decryptLicense(String cipherText) {
    String plainText = decryptWithRSA(cipherText, privateKey);
    System.out.println("Server -- Decrypted Text: " + plainText);
    return plainText;
  }

  /**
   * Sign the license using sign method with given hash using private key
   * 
   * @param hash
   * @return signature
   */
  private String signLicense(String hash) {
    String signature = BinaryToString(sign(hash, privateKey));
    System.out.println("Server -- Digital Signature: " + signature);
    return signature;
  }

  /**
   * Decryptes the cipher text using RSA with given private key
   * 
   * @param cipherText
   * @param privateKey
   * @return plaintext
   */
  private static String decryptWithRSA(String cipherText, PrivateKey privateKey) {
    String ret = null;

    try {
      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      ret = BinaryToString(cipher.doFinal(StringToBinary(cipherText)));
    } catch (Exception e) {
      System.out.println("ERROR:: Cannot do decryption on given string, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Creates md5 hash of given text
   * 
   * @param text
   * @return md5 hash
   */
  private static String createMD5Hash(String text) {
    String ret = null;

    try {
      byte[] messageDigest = MessageDigest.getInstance("MD5").digest(StringToBinary(text));

      ret = new BigInteger(1, messageDigest).toString(16);
      while (ret.length() < 32)
        ret = "0" + ret;
    } catch (NoSuchAlgorithmException e) {
      System.out.println("ERROR:: Cannot do hashing operation on given string, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Signs the given text using SHA256WithRSA with given private key
   * 
   * @param text
   * @param privateKey
   * @return signature as byte array
   */
  private static byte[] sign(String text, PrivateKey privateKey) {
    byte[] ret = null;

    try {
      Signature signature = Signature.getInstance(SIGN_ALGORITHM);
      signature.initSign(privateKey);
      ret = signature.sign();
    } catch (Exception e) {
      System.out.println("ERROR:: Cannot do sign operation, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Get private key from the private key path and create encoded key for rsa with
   * x509 standarts
   * 
   * @return private key
   */
  private static PrivateKey getPrivateKey() {
    PrivateKey ret = null;

    try {
      byte[] keyBytes = readBinaryFile(PRIVATE_KEY_PATH);
      KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
      PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
      ret = keyFactory.generatePrivate(encodedKeySpec);
    } catch (Exception e) {
      System.out.println("Cannot retrieve private key, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Read file as a binary with given filename
   * 
   * @param filename
   * @return byte array of the file
   */
  private static byte[] readBinaryFile(String filename) {
    byte[] ret = null;
    File file = new File(filename);

    try {
      try {
        ret = Files.readAllBytes(file.toPath());
      } catch (NoSuchFileException e) {
        file.createNewFile();
        return null;
      }
    } catch (IOException e) {
      System.out.println("ERROR:: Cannot read file " + filename + ", exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Convert string to binary
   * 
   * @param str
   * @return byte array of given string
   */
  private static byte[] StringToBinary(String str) {
    return str.getBytes(StandardCharsets.ISO_8859_1);
  }

  /**
   * Convert given byte array to string
   * 
   * @param bytes
   * @return string of given byte array
   */
  private static String BinaryToString(byte[] bytes) {
    return new String(bytes, StandardCharsets.ISO_8859_1);
  }
}
