import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';
import 'package:flutter/services.dart';

class DatabaseService {
  static Database? _database;

  // Initialize SQLite database
  static Future<Database> get database async {
    if (_database != null) return _database!;

    // If the database is not yet created, initialize it
    _database = await _initializeDatabase();
    return _database!;
  }

  // Open the database and create necessary tables if they don't exist
  static Future<Database> _initializeDatabase() async {
    final databasesPath = await getDatabasesPath();
    final path = join(databasesPath, 'seed_data.db');
    
    return await openDatabase(path, version: 1, onCreate: (db, version) async {
      await db.execute('''
        CREATE TABLE seeds (
          id INTEGER PRIMARY KEY,
          encrypted_seed TEXT NOT NULL,
          passphrase_hash TEXT NOT NULL
        )
      ''');
    });
  }

  // Save encrypted seed phrase into the database
  static Future<void> saveEncryptedSeed(String encryptedSeed, String passphrase) async {
    final db = await database;
    
    // Insert encrypted seed data and passphrase hash into the database
    await db.insert(
      'seeds', 
      {
        'encrypted_seed': encryptedSeed, 
        'passphrase_hash': passphrase, 
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  // Retrieve the encrypted seed based on the passphrase
  static Future<String?> getEncryptedSeed(String passphrase) async {
    final db = await database;

    // Query the database for the encrypted seed using the passphrase hash
    final result = await db.query(
      'seeds', 
      where: 'passphrase_hash = ?', 
      whereArgs: [passphrase],
    );

    if (result.isNotEmpty) {
      return result.first['encrypted_seed'] as String;
    }
    return null;
  }
}
