# Client Auth

## Motivation

WalletConnect supports e2e encrypted messaging between multiple clients.
Should a recipient be offline, WalletConnect stores the encrypted messages in the recipient's mailbox until they reconnect.
The address of the mailbox is a unique sticky _client id_ that clients present when they connect to WalletConnect.

This document discusses the creation and usage of the _client id_.

## Overview

WalletConnect expects an `Authentication Bearer <signed nonce>` header when establishing the Websocket connection.
WalletConnect exposes a `HTTP GET /auth-nonce?<client id>` endpoint to retrieve a nonce.

The `client id` is the public key of a public/private key pair that clients genererate when instantiating the SDK and keep for the entire lifecycle.

The Bearer is a standard JWT token.

## Key Pair and JWT Creation

### Test Cases

```JavaScript
// Client will sign the Server assigned socketId as a nonce
const nonce = 'c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e';

// Fixed seed to generate the same key pair
const seed = fromString('58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295','base16');

// Generate key pair from seed
const keyPair = ed25519.generateKeyPairFromSeed(seed);

// Expected JWT for given nonce
const expected = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ojg4NGFiNjdmNzg3YjY5ZTUzNGJmZGJhOGQ1YmViNGU3MTk3MDBlOTBhYzA2MzE3ZWQxNzdkNDllNWEzM2JlNWEiLCJzdWIiOiJjNDc5ZmU1ZGM0NjRlNzcxZTc4YjE5M2QyMzlhNjViNThkMjc4Y2FkMWMzNGJmYjBiNTcxNmU1YmI1MTQ5MjhlIn0.FsPtV_vLm_i7pMMCKWdE08zFo0PEvfBGI4nvMNnsl-Z2ML-I6PSThUlJEfGo4C4G9Y9zMr1ydLtiFNEv7l6AAw"

async function test() {
  const jwt = await signJWT(nonce, keyPair)
  console.log('jwt', jwt)
  console.log('matches', jwt === expected)
  const verified = await verifyJWT(jwt)
  console.log('verified', verified)
}

test()
```

### API

```JavaScript
import * as ed25519 from '@stablelib/ed25519';
import { fromString } from 'uint8arrays/from-string';
import { toString } from 'uint8arrays/to-string';
import { safeJsonParse, safeJsonStringify } from "@walletconnect/safe-json";

// ---------- Interfaces ----------------------------------------------- //

interface IridiumJWTHeader {
  alg: "EdDSA";
  typ: "JWT";
}

interface IridiumJWTPayload {
  iss: string;
  sub: string;
}

interface IridiumJWTParams {
  header: IridiumJWTHeader;
  payload: IridiumJWTPayload;
}

interface IridiumJWTSigned extends IridiumJWTParams {
  signature: Uint8Array;
}

// ---------- Constants ----------------------------------------------- //

const JWT_IRIDIUM_ALG: IridiumJWTHeader["alg"] = "EdDSA"

const JWT_IRIDIUM_TYP: IridiumJWTHeader["typ"] = "JWT"

const JWT_DELIMITER = "."

const DID_DELIMITER = ":"

const DID_KEY_PREFIX = "did:key"

// ---------- Utilities ----------------------------------------------- //

function decodeJSON(str: string): any {
  return safeJsonParse(toString(fromString(str, 'base64url'), 'utf8'))
}

function encodeJSON(val: any): string {
  return toString(fromString(safeJsonStringify(val), 'utf8'), 'base64url')
}

function encodeIss(publicKey: Uint8Array): string {
  return `${DID_KEY_PREFIX}:${toString(keyPair.publicKey, "hex")}`
}

function decodeIss(issuer: string): Uint8Array {
  if (!issuer.startsWith(DID_KEY_PREFIX)) {
    throw new Error(`Issuer must be a DID with method "key"`)
  }
  const params = issuer.split(DID_DELIMITER)
  if (params[2].length !== 64) {
    throw new Error(`Issuer key must be 32 bytes`)
  }
  return fromString(params[2], 'hex')
}

function encodeSig(bytes: Uint8Array): string {
  return toString(bytes, 'base64url')
}

function decodeSig(encoded: string): Uint8Array {
  return fromString(encoded, 'base64url')
}

function encodeParams(params: IridiumJWTParams): string {
  return [
    encodeJSON(params.header),
    encodeJSON(params.payload)
  ].join(JWT_DELIMITER)
}

function decodeParams(jwt: string): IridiumJWTParams {
  const params = jwt.split(JWT_DELIMITER)
  const header = decodeJSON(params[0])
  const payload = decodeJSON(params[1])
  return { header, payload }
}

function encodeJWT(params: IridiumJWTSigned): string {
  return [
    encodeJSON(params.header),
    encodeJSON(params.payload),
    encodeSig(params.signature)
  ].join(JWT_DELIMITER)
}

function decodeJWT(jwt: string): IridiumJWTSigned {
  const params = jwt.split(JWT_DELIMITER)
  const header = decodeJSON(params[0])
  const payload = decodeJSON(params[1])
  const signature = decodeSig(params[2])
  return { header, payload, signature }
}

// ---------- API ----------------------------------------------- //

async function signJWT(subject: string, keyPair: ed25519.KeyPair) {
  const header = { "alg": JWT_IRIDIUM_ALG, "typ": JWT_IRIDIUM_TYP }
  const publicKey = toString(keyPair.publicKey, "hex")
  const issuer = `did:key:${publicKey}`
  const payload = { "iss": issuer, "sub": subject }
  const dataToSign = fromString(encodeParams({ header, payload }), "utf8")
  const signature = ed25519.sign(keyPair.secretKey, dataToSign)
  return encodeJWT({ header, payload, signature })
}

async function verifyJWT(jwt: string) {
  const { header, payload, signature } = decodeJWT(jwt)
  if (header.alg !== JWT_IRIDIUM_ALG || header.typ !== JWT_IRIDIUM_TYP) {
    throw new Error('JWT must use EdDSA algorithm')
  }
  const publicKey = decodeIss(payload.iss)
  const dataToSign = fromString(encodeParams({ header, payload }), "utf8")
  return ed25519.verify(publicKey, dataToSign, signature)
}
```