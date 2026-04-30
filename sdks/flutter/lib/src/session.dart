part of '../sibna_flutter.dart';

class SibnaSession {
  final Pointer<Void> _handle;
  final Uint8List peerId;
  bool _disposed = false;

  SibnaSession._(this._handle, this.peerId);

  /// Encrypt [plaintext] for this session.
  ///
  /// [associatedData] is optional authenticated context data
  /// (e.g. message ID, timestamp). Must match on decrypt.
  Future<Uint8List> encrypt(
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    // For session-based E2E, key derivation happens inside the native layer.
    _ensureNotDisposed();
    if (_handle == null || _handle == nullptr) {
      throw SibnaError(SibnaErrorCode.invalidState, 'Session not initialised — call via SibnaContext.createSession()');
    }

    final keyPtr  = SibnaCrypto._copyToNative(plaintext);
    final adPtr   = associatedData != null ? SibnaCrypto._copyToNative(associatedData) : nullptr;
    final outBuf  = calloc<_ByteBuffer>();
    try {
      SibnaCrypto._checkResult(
        SibnaFlutter.bindings.sibna_session_encrypt(
          _handle!, keyPtr, plaintext.length,
          adPtr, associatedData?.length ?? 0, outBuf,
        ),
        op: 'session_encrypt',
      );
      final result = SibnaCrypto._readAndFreeBuffer(outBuf);
      _messagesSent++;
      return result;
    } finally {
      calloc.free(keyPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(outBuf);
    }
  }

  /// Decrypt [ciphertext] from this session peer.
  Future<Uint8List> decrypt(
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();
    if (_handle == null || _handle == nullptr) {
      throw SibnaError(SibnaErrorCode.invalidState, 'Session not initialised');
    }

    final ctPtr  = SibnaCrypto._copyToNative(ciphertext);
    final adPtr  = associatedData != null ? SibnaCrypto._copyToNative(associatedData) : nullptr;
    final outBuf = calloc<_ByteBuffer>();
    try {
      SibnaCrypto._checkResult(
        SibnaFlutter.bindings.sibna_session_decrypt(
          _handle!, ctPtr, ciphertext.length,
          adPtr, associatedData?.length ?? 0, outBuf,
        ),
        op: 'session_decrypt',
      );
      final result = SibnaCrypto._readAndFreeBuffer(outBuf);
      _messagesReceived++;
      return result;
    } finally {
      calloc.free(ctPtr);
      if (adPtr != nullptr) calloc.free(adPtr);
      calloc.free(outBuf);
    }
  }

  /// Dispose the session handle and free native resources.
  void dispose() {
    if (_disposed) return;
    SibnaFlutter.bindings.sibna_session_destroy(_handle);
    _disposed = true;
  }

  void _ensureNotDisposed() {
    if (_disposed) throw const SibnaError(
      SibnaErrorCode.invalidState, 'Session has been disposed',
    );
  }

  @override
  String toString() =>
      'SibnaSession(peer: ${peerId.take(4).toList()}, disposed: $_disposed)';
}
