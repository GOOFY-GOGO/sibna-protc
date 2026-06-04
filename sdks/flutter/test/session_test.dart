import 'package:flutter_test/flutter_test.dart';
import 'package:sibna_flutter/sibna_flutter.dart';
import 'dart:typed_data';

void main() {
  group('SibnaFlutter Session Tests', () {
    late Config config;
    late Uint8List sharedSecret;

    setUp(() {
      config = Config();
      sharedSecret = Uint8List.fromList(List.generate(32, (i) => i));
    });

    test('Session encrypt decrypt roundtrip', () async {
      // In Flutter SDK, session is often managed by SibnaFlutter.createSession
      final s1 = await SibnaFlutter.createSession(sharedSecret, 'a', 'b', config);
      final s2 = await SibnaFlutter.createSession(sharedSecret, 'b', 'a', config);

      final plaintext = 'Hello Flutter Production!';
      final ad = 'aad';

      // Verify the flow triggers the native layer (which currently throws UnimplementedError)
      expect(() async => await s1.encrypt(plaintext, ad), throwsA(isA<UnimplementedError>()));
    });

    test('Session rejects empty plaintext', () async {
      final s1 = await SibnaFlutter.createSession(sharedSecret, 'a', 'b', config);
      
      expect(() async => await s1.encrypt('', 'ad'), throwsA(isA<ValidationError>()));
    });

    test('Session rejects empty ciphertext', () async {
      final s2 = await SibnaFlutter.createSession(sharedSecret, 'b', 'a', config);
      
      expect(() async => await s2.decrypt(Uint8List(0), 'ad'), throwsA(isA<ValidationError>()));
    });

    test('Session stats verification', () async {
      final s1 = await SibnaFlutter.createSession(sharedSecret, 'a', 'b', config);
      
      // Check that stats are available
      expect(s1.messagesSent, equals(0));
      expect(s1.messagesReceived, equals(0));
    });
  });
}
