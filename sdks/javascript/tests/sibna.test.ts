/**
 * Sibna Protocol JavaScript/TypeScript SDK — Unit Tests
 */

import {
  VERSION,
  padPayload,
  unpadPayload,
  generateIdentity,
  SibnaError,
  AuthError,
  NetworkError,
  CryptoError,
} from '../src/index';

describe('VERSION', () => {
  it('should be 3.0.0', () => {
    expect(VERSION).toBe('3.0.1');
  });
});

describe('Padding', () => {
  it('should pad and unpad roundtrip', () => {
    const data = new TextEncoder().encode('Hello, World!');
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should pad empty data', () => {
    const data = new Uint8Array(0);
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should pad large data', () => {
    const data = new Uint8Array(5000).fill(0x42);
    const padded = padPayload(data);
    expect(padded.length % 1024).toBe(0);
    const unpadded = unpadPayload(padded);
    expect(unpadded).toEqual(data);
  });

  it('should throw on empty unpad', () => {
    expect(() => unpadPayload(new Uint8Array(0))).toThrow(CryptoError);
  });
});

describe('Errors', () => {
  it('SibnaError should have statusCode', () => {
    const err = new SibnaError('test', 400);
    expect(err.message).toBe('test');
    expect(err.statusCode).toBe(400);
  });

  it('AuthError should have name', () => {
    const err = new AuthError('auth failed', 401);
    expect(err.name).toBe('AuthError');
    expect(err.statusCode).toBe(401);
  });

  it('NetworkError should have name', () => {
    const err = new NetworkError('network failed', 503);
    expect(err.name).toBe('NetworkError');
    expect(err.statusCode).toBe(503);
  });

  it('CryptoError should have name', () => {
    const err = new CryptoError('crypto failed');
    expect(err.name).toBe('CryptoError');
  });
});

describe('Identity', () => {
  it('should generate identity', async () => {
    const identity = await generateIdentity();
    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.privateKey).toBeInstanceOf(Uint8Array);
    expect(identity.publicKey.length).toBe(32);
    expect(identity.privateKey.length).toBe(32);
  });

  it('should generate unique identities', async () => {
    const id1 = await generateIdentity();
    const id2 = await generateIdentity();
    expect(id1.publicKey).not.toEqual(id2.publicKey);
  });
});
