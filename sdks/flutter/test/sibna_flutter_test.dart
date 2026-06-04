import 'package:flutter_test/flutter_test.dart';
import 'package:sibna_flutter/sibna_flutter.dart';

void main() {
  test('SibnaFlutter identity generation', () async {
    final identity = await SibnaFlutter.generateIdentity();
    expect(identity.publicKey.length, 32);
  });

  test('SibnaFlutter session encrypt decrypt', () async {
    final config = Config();
    final sharedSecret = List<int>.generate(32, (i) => i);
    
    final s1 = await SibnaFlutter.createSession(sharedSecret, 'a', 'b', config);
    final s2 = await SibnaFlutter.createSession(sharedSecret, 'b', 'a', config);

    final plaintext = 'Hello Flutter!';
    final ciphertext = await s1.encrypt(plaintext, 'ad');
    final decrypted = await s2.decrypt(ciphertext, 'ad');
    
    expect(decrypted, equals(plaintext));
  });
}
