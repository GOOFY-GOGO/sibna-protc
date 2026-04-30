part of '../sibna_flutter.dart';

class SibnaGroupMessage {
  final Uint8List groupId;
  final Uint8List ciphertext;
  final int epoch;
  final int timestamp;

  const SibnaGroupMessage({
    required this.groupId,
    required this.ciphertext,
    required this.epoch,
    required this.timestamp,
  });
}

/// Group session — sender-key based group E2EE.
class SibnaGroup {
  final Uint8List groupId;
  final Pointer<Void> _handle;
  bool _disposed = false;

  SibnaGroup._(this.groupId, this._handle);

  /// Create a new group with a cryptographically random 32-byte group ID.
  static SibnaGroup create() {
    final groupIdPtr  = calloc<Uint8>(32);
    final handlePtr   = calloc<Pointer<Void>>();
    try {
      // Generate the group ID via the native RNG
      SibnaCrypto._checkResult(
        SibnaFlutter.bindings.sibna_random_bytes(32, groupIdPtr),
        op: 'group_create/random_bytes',
      );
      // Create the native group context
      SibnaCrypto._checkResult(
        SibnaFlutter.bindings.sibna_group_create(groupIdPtr, 32, handlePtr),
        op: 'group_create',
      );
      final groupId = Uint8List.fromList(groupIdPtr.asTypedList(32));
      return SibnaGroup._(groupId, handlePtr.value);
    } finally {
      calloc.free(groupIdPtr);
      calloc.free(handlePtr);
    }
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    SibnaFlutter.bindings.sibna_group_destroy(_handle);
  }

  @override
  String toString() => 'SibnaGroup(id: ${groupId.take(4).toList()})';
}
