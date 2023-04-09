import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class Client {
  private static PublicKey publicKey;
  private static String diskSerialNumber;
  private static String motherboardSerialNumber;
  private static String macAddress;

  // Constants
  private static final String USERNAME = "abt";
  private static final String SERIAL_NUMBER = "1234-5678-9012";
  public static final String RSA_ALGORITHM = "RSA";
  public static final String PUBLIC_KEY_PATH = "public.key";
  public static final String SIGN_ALGORITHM = "SHA256WithRSA";
  public static final String LICENSE_FILE = "license.txt";

  public static void main(String[] args) {
    // Retrieve necessary elements
    publicKey = getPublicKey();
    macAddress = getMacAddress();
    motherboardSerialNumber = getMotherboardSerialNumber();
    diskSerialNumber = getDiskSerialNumber();

    // Initialize the client
    System.out.println("Client started...");
    System.out.println("My MAC: " + macAddress);
    System.out.println("My Disk ID: " + diskSerialNumber);
    System.out.println("My Motherboard ID: " + motherboardSerialNumber);

    // Initialize the license manager -- instance is used instead of static class
    // since it seemed more realistic
    LicenseManager licenseManager = new LicenseManager();

    // Read license file
    byte[] signature = readBinaryFile(LICENSE_FILE);
    if (signature == null) {
      System.out.println("Client -- License file is not found.");
    } else {
      String signatureNormalized = BinaryToString(signature);

      if (!verifyLicense(signatureNormalized)) {
        System.out.println("Client -- The license file has been broken!!");
      } else {
        System.out.println("Client -- Succeed. The license is correct.");
        return;
      }
    }

    // Start licensing process
    String cipherText = createEncryptedLicense();
    String hash = createHash(cipherText);
    licenseManager.start(hash, cipherText);
  }

  /**
   * Construct the client data and encrypt it with rsa using public key
   * 
   * @return encrypted license file
   */
  private static String createEncryptedLicense() {
    String clientData = USERNAME + "$" + SERIAL_NUMBER + "$" + macAddress + "$" + diskSerialNumber + "$"
        + motherboardSerialNumber;

    String cipherText = encryptWithRSA(clientData, publicKey);

    System.out.println("Client -- Raw License Text: " + clientData);
    System.out.println("Client -- Encrypted License Text: " + cipherText);

    return cipherText;
  }

  /**
   * Save license file if the license successfully signed by license manager
   * 
   * @param signature
   */
  public static void saveLicense(String signature) {
    if (!verifyLicense(signature)) {
      System.out.println("Client -- The license file has been broken!!");
      System.exit(1);
      return;
    }

    writeFile(LICENSE_FILE, signature);
    System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
  }

  /**
   * Create md5 hash of a given string
   * 
   * @param cipherText
   * @return md5 hash
   */
  private static String createHash(String cipherText) {
    String hash = createMD5Hash(cipherText);
    System.out.println("Client -- MD5 License Text: " + hash);
    return hash;
  }

  /**
   * Verify license using verify method
   * 
   * @param signature
   * @return
   */
  private static boolean verifyLicense(String signature) {
    return verify(signature, publicKey);
  }

  /**
   * Encrypt given plaintext with RSA using given public key
   * 
   * @param plainText
   * @param publicKey
   * @return encrypted cipher text
   */
  private static String encryptWithRSA(String plainText, PublicKey publicKey) {
    String ret = null;

    try {
      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      ret = BinaryToString(cipher.doFinal(StringToBinary(plainText)));
    } catch (Exception e) {
      System.out.println("ERROR:: Cannot do encrpytion on given string, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Verify a signature by using given public key
   * 
   * @param signature
   * @param publicKey
   * @return true if verification succeeds, false otherwise
   */
  private static boolean verify(String signature, PublicKey publicKey) {
    try {
      Signature verifySignature = Signature.getInstance(SIGN_ALGORITHM);
      verifySignature.initVerify(publicKey);
      return verifySignature.verify(StringToBinary(signature));
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Write given data to given filename
   * 
   * @param filename
   * @param data
   */
  private static void writeFile(String filename, String data) {
    try {
      File file = new File(filename);
      Files.write(file.toPath(), StringToBinary(data));
    } catch (IOException e) {
      System.out.println("ERROR:: Cannot write to file " + filename + ", exiting...");
      System.exit(1);
    }
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
   * Get public key from the public key path and create encoded key for rsa with
   * x509 standarts
   * 
   * @return public key
   */
  private static PublicKey getPublicKey() {
    PublicKey ret = null;

    try {
      byte[] keyBytes = readBinaryFile(PUBLIC_KEY_PATH);
      KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
      X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keyBytes);
      ret = keyFactory.generatePublic(encodedKeySpec);
    } catch (Exception e) {
      System.out.println("Cannot retrieve public key, exiting...");
      System.exit(1);
    }

    return ret;
  }

  /**
   * Create md5 hash of given string
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

  /**
   * Run command for retrieving the motherboard serial number on windows
   * 
   * @return motherboard serial number
   */
  private static String getMotherboardSerialNumber() {
    return runProcess("wmic baseboard get serialnumber").split("SerialNumber")[1];
  }

  /**
   * Run command for retrieving the disk serial number on windows
   * 
   * @return disk serial number
   */
  private static String getDiskSerialNumber() {
    return runProcess("wmic diskdrive get serialnumber").split("SerialNumber")[1];
  }

  /**
   * Run command for retrieving mac address on windows
   * 
   * @return mac address
   */
  private static String getMacAddress() {
    return String.join(":",
        runProcess("ipconfig/all|find \"Physical Address\"").split("Physical Address. . . . . . . . . : ")[1].trim()
            .split("-"));

  }

  /**
   * Run command line argument process on windows
   * 
   * @param command
   * @return result of command line process
   */
  private static String runProcess(String command) {
    String ret = "";

    try {
      Process process = Runtime.getRuntime().exec("cmd.exe /c " + command);
      InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
      BufferedReader bufferedReader = new BufferedReader(inputStreamReader);

      String readline;
      while ((readline = bufferedReader.readLine()) != null) {
        ret += readline.trim();

      }

      process.waitFor();
      bufferedReader.close();
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("ERROR :: Cannot retrieve information from command line");
      System.exit(1);
      ret = null;
    }

    return ret;
  }
}
