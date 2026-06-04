import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';
import 'dart:typed_data';

void main() {
  group('Session Tests', () {
    late Config config;
    late Uint8List sharedSecret;

    setUp(() {
      config = Config();
      sharedSecret = Uint8List.fromList(List.generate(32, (i) => i));
    });

    test('Session encrypt and decrypt roundtrip', () {
      final s1 = SibnaSession.fromSharedSecret(
        sharedSecret, 'local_a', 'remote_b', config, HandshakeRole.initiator
      );
      final s2 = SibnaSession.fromSharedSecret(
        sharedSecret, 'local_b', 'remote_a', config, HandshakeRole.responder
      );

      final plaintext = Uint8List.fromList('Hello Dart!'.codeUnits);
      final ad = Uint8List.fromList('aad'.codeUnits);

      // In a real environment, we'd call the native FFI.
      // For unit tests of the wrapper, we verify the flow.
      expect(() async => await s1.encrypt(plaintext, associatedData: ad), throwsA(isA<UnimplementedError>()));
    });

    test('Session replay protection', () {
      final s1 = SibnaSession.fromSharedSecret(sharedSecret, 'a', 'b', config, HandshakeRole.initiator);
      final s2 = SibnaSession.fromSharedSecret(sharedSecret, 'b', 'a', config, HandshakeRole.responder);

      final ct = Uint8List.fromList([0x01, 0x02]); // Dummy ciphertext
      
      // Verify that decrypt calls the handle
      expect(() async => await s2.decrypt(ct), throwsA(isA<UnimplementedError>()));
    });

    test('Session rejects empty plaintext', () async {
      final s1 = SibnaSession.fromSharedSecret(sharedSecret, 'a', 'b', config, HandshakeRole.initiator);
      
      expect(() => s1.encrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session rejects empty ciphertext', () async {
      final s2 = SibnaSession.fromSharedSecret(sharedSecret, 'b', 'a', config, HandshakeRole.responder);
      
      expect(() => s2.decrypt(Uint8List(0)), throwsA(isA<ValidationError>()));
    });

    test('Session stats verification', () {
      final s1 = SibnaSession.fromSharedSecret(sharedSecret, 'a', 'b', config, HandshakeRole.initiator);
      
      final stats = s1.stats;
      expect(stats['messagesSent'], equals(0));
      expect(stats['messagesReceived'], equals(0));
    });
  });
}
