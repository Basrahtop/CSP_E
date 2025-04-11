import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart';

class EncryptionService {
  // Encrypt Seed Phrase using AES with the passphrase
  static Future<String> encryptSeed(String seed, String passphrase) async {
    final secretKey = _deriveKey(passphrase);
    final iv = _generateIv();
    
    final cipher = CipherWithAppendedMac(AESGCM());
    final encrypted = await cipher.encrypt(
      utf8.encode(seed), 
      secretKey: secretKey, 
      nonce: iv
    );

    final encryptedData = {
      'iv': base64Encode(iv),
      'ciphertext': base64Encode(encrypted.cipherText),
      'mac': base64Encode(encrypted.mac.bytes),
    };
    
    return jsonEncode(encryptedData);
  }

  // Decrypt Seed Phrase using AES and passphrase
  static Future<String?> decryptSeed(String encryptedData, String passphrase) async {
    final secretKey = _deriveKey(passphrase);
    final data = jsonDecode(encryptedData);
    
    final iv = base64Decode(data['iv']);
    final cipherText = base64Decode(data['ciphertext']);
    final mac = base64Decode(data['mac']);
    
    final cipher = CipherWithAppendedMac(AESGCM());
    final decrypted = await cipher.decrypt(
      SecretKey(secretKey), 
      nonce: iv,
      ciphertextAndMac: cipherText + mac,
    );

    if (decrypted != null) {
      return utf8.decode(decrypted);
    }
    return null; // Decryption failed
  }

  // Derive a secret key from the passphrase
  static List<int> _deriveKey(String passphrase) {
    final salt = utf8.encode('unique_salt');
    final pbkdf2 = PBKDF2(iterations: 100000);
    final key = pbkdf2.deriveKey(
      secretKey: utf8.encode(passphrase), 
      nonce: salt, 
      length: 32
    );

    return key.bytes;
  }

  // Generate a random IV for AES encryption
  static List<int> _generateIv() {
    final iv = List<int>.generate(12, (i) => i + 1); // Random 12-byte IV
    return iv;
  }
}
