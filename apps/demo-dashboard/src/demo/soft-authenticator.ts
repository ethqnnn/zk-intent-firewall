/**
 * A software WebAuthn authenticator: a P-256 key pair that produces real attestation ("none") and
 * assertion responses, byte for byte as a platform authenticator does, with genuine ECDSA
 * signatures. It lets the headless demo and the tests run the passkey flow without a browser,
 * and lets tests build precisely broken responses.
 *
 * It is not a passkey: its private key lives in this process. Never use it outside demos and tests.
 */
import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

export interface SoftAuthenticatorOptions {
  readonly origin: string;
  readonly rpId: string;
}

/** Everything a test may want to change in one assertion. */
export interface AssertionOverrides {
  readonly origin?: string;
  readonly rpId?: string;
  readonly type?: string;
  readonly challenge?: string;
  /** Flags byte. Default UP | UV. */
  readonly flags?: number;
  /** Signature counter to report. Default: the next value. */
  readonly counter?: number;
  /** Sign with this key instead of the credential's. */
  readonly signingKey?: KeyObject;
  /** Report this credential ID. */
  readonly credentialId?: string;
  /** Change the signed bytes after signing (the signature then no longer matches). */
  readonly tamperAuthData?: (authData: Uint8Array) => Uint8Array;
  readonly tamperClientData?: (clientDataJSON: string) => string;
  readonly tamperSignature?: (signature: Uint8Array) => Uint8Array;
}

export class SoftAuthenticator {
  readonly origin: string;
  readonly rpId: string;
  readonly credentialIdBytes: Uint8Array<ArrayBuffer>;
  readonly #privateKey: KeyObject;
  readonly #publicKey: KeyObject;
  #counter = 0;

  constructor(o: SoftAuthenticatorOptions) {
    this.origin = o.origin;
    this.rpId = o.rpId;
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
    this.credentialIdBytes = new Uint8Array(randomBytes(32));
  }

  get credentialId(): string {
    return isoBase64URL.fromBuffer(this.credentialIdBytes);
  }

  /** A fresh, unrelated P-256 key, for signing with the wrong key. */
  static otherKey(): KeyObject {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  }

  #rpIdHash(rpId: string): Uint8Array<ArrayBuffer> {
    return new Uint8Array(createHash('sha256').update(rpId).digest());
  }

  #cosePublicKey(): Uint8Array<ArrayBuffer> {
    const jwk = this.#publicKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x!, 'base64url');
    const y = Buffer.from(jwk.y!, 'base64url');
    // COSE_Key: kty EC2 (2), alg ES256 (-7), crv P-256 (1), x, y.
    return new Uint8Array(isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(x)],
        [-3, new Uint8Array(y)],
      ]),
    ));
  }

  /** The response navigator.credentials.create would return for these options. */
  createRegistrationResponse(options: { challenge: string }, o: { flags?: number; origin?: string; rpId?: string } = {}) {
    const clientDataJSON = JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: o.origin ?? this.origin, crossOrigin: false });
    const counter = Buffer.alloc(4);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialIdBytes.length);
    const authData = Buffer.concat([
      this.#rpIdHash(o.rpId ?? this.rpId),
      Buffer.from([o.flags ?? FLAG_UP | FLAG_UV | FLAG_AT]),
      counter,
      Buffer.alloc(16), // AAGUID: none
      idLen,
      this.credentialIdBytes,
      this.#cosePublicKey(),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, unknown>()],
        ['authData', new Uint8Array(authData)],
      ]) as Parameters<typeof isoCBOR.encode>[0],
    );
    return {
      id: this.credentialId,
      rawId: this.credentialId,
      type: 'public-key' as const,
      response: {
        clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
        attestationObject: isoBase64URL.fromBuffer(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  /** The response navigator.credentials.get would return for `challenge`. */
  createAssertion(challenge: string, o: AssertionOverrides = {}) {
    const clientDataJSON = JSON.stringify({ type: o.type ?? 'webauthn.get', challenge: o.challenge ?? challenge, origin: o.origin ?? this.origin, crossOrigin: false });
    const counterValue = o.counter ?? ++this.#counter;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(counterValue);
    const authData = new Uint8Array(Buffer.concat([this.#rpIdHash(o.rpId ?? this.rpId), Buffer.from([o.flags ?? FLAG_UP | FLAG_UV]), counter]));
    const signed = Buffer.concat([authData, createHash('sha256').update(clientDataJSON).digest()]);
    let signature: Uint8Array<ArrayBuffer> = new Uint8Array(sign('sha256', signed, { key: o.signingKey ?? this.#privateKey, dsaEncoding: 'der' }));
    const finalAuthData = new Uint8Array(o.tamperAuthData ? o.tamperAuthData(authData) : authData);
    const finalClientData = o.tamperClientData ? o.tamperClientData(clientDataJSON) : clientDataJSON;
    if (o.tamperSignature) signature = new Uint8Array(o.tamperSignature(signature));
    const id = o.credentialId ?? this.credentialId;
    return {
      id,
      rawId: id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: isoBase64URL.fromUTF8String(finalClientData),
        authenticatorData: isoBase64URL.fromBuffer(finalAuthData),
        signature: isoBase64URL.fromBuffer(signature),
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}

export const AUTHENTICATOR_FLAGS = { UP: FLAG_UP, UV: FLAG_UV, AT: FLAG_AT } as const;
