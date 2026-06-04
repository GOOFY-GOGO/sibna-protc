import 'package:test/test.dart';
import 'package:sibna_protocol/sibna_protocol.dart';

void main() {
  group('Identity Tests', () {
    test('Identity generation produces valid keys', () {
      final identity = IdentityKeyPair.generate();
      expect(identity.publicKey.length, 32);
      expect(identity.privateKey, isNotNull);
    });

    test('Identity sign and verify', () {
      final identity = IdentityKeyPair.generate();
      final data = 'test data'.codeUnits;
      
      final signature = identity.sign(data);
      expect(signature.length, 64);
      
      expect(IdentityKeyPair.verify(identity.publicKey, data, signature), isTrue);
    });

    test('Identity from seed roundtrip', () {
      final seed = List<int>.filled(32, 0xAB);
      final identity1 = IdentityKeyPair.fromSeed(seed);
      final identity2 = IdentityKeyPair.fromSeed(seed);
      
      expect(identity1.publicKey, equals(identity2.publicKey));
    });
  });
}
