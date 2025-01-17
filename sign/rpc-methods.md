# RPC Methods

This doc should be used as a _source-of-truth_ and reflect the latest decisions and changes applied to the WalletConnect collection of client-to-client JSON-RPC methods for all platforms SDKs.

## Definitions

- **Nullables:** Fields flagged as `Optional` can be ommited from the payload.
- Unless explicitly mentioned that a response requires associated data, all methods response's follow a default JSON-RPC pattern for the success and failure cases:

```jsonc
// Success
result: true

// Failure
error: {
  "code": number,
  "message": string
}
```

## Pairings:

### wc_sessionPropose

Used to propose a session through topic A. Requires a success response with associated data.

- Success response is equivalent to session approval.
- Error response is equivalent to session rejection.
- This method _might_ require a special timeout, because it needs end-user interaction to respond.
- Proposer must use the relay parameter selected and sent by the responder, if different than the proposed one.

```jsonc
// wc_sessionPropose params
{
  "relays": [
    {
      "protocol": string,
      "data": string // Optional
    },
  ],
  "proposer": {
    "publicKey": string,
    "metadata": {
      "name": string,
      "description": string,
      "url": string,
      "icons": [string]
    }
  },
  "requiredNamespaces": {
    "<namespace_name>" : {
      "chains": [string],
      "methods": [string],
      "events": [string],
      "extension": [ // optional
        {
          "chains": [string],
          "methods": [string],
          "events": [string],
        }
      ]
    }
  },
}
```

```jsonc
// Success result
{
  "relay": {
    "protocol": string,
    "data": string // Optional
  },
  "responderPublicKey": string,
}
```

### wc_pairingDelete

Used to inform the peer to close and delete a pairing. All associated sessions of the given pairing must also be deleted.

```jsonc
// wc_pairingDelete params
{
  "code": Int64,
  "message": string
}
```

### wc_pairingPing

```jsonc
// wc_pairingPing params
{
  // empty
}
```

## Sessions:

### wc_sessionSettle

Used to settle a session over topic B.

```jsonc
// wc_sessionSettle params
{
  "relay": {
    "protocol": string,
    "data": string // Optional
  },
  "controller": {
    "publicKey": string,
    "metadata": {
      "name": string,
      "description": string,
      "url": string,
      "icons": [string]
    }
  },
  "namespaces": {
    "<namespace_name>" : {
      "accounts": [string],
      "methods": [string],
      "events": [string],
      "extension": [ // optional
        {
          "accounts": [string],
          "methods": [string],
          "events": [string],
        }
      ]
    }
  },
  "expiry": Int64, // seconds
}
```

### wc_sessionUpdate

```jsonc
// wc_sessionUpdate params
{
  "namespaces": {
    "<namespace_name>" : {
      "accounts": [string],
      "methods": [string],
      "events": [string],
      "extension": [ // optional
        {
          "accounts": [string],
          "methods": [string],
          "events": [string],
        }
      ]
    }
  }
}
```

### wc_sessionExtend

Used to extend the lifetime of a session.

- The expiry is the absolute timestamp of the expiration date, in seconds.

```jsonc
// wc_sessionExtend params
{
  "expiry": number
}
```

### wc_sessionDelete

Used to inform the peer to close and delete a session. The reason field should be a human-readable message defined by the SDK consumer to be shown on the peer's side.

```jsonc
// wc_sessionDelete params
{
  "code": Int64,
  "message": string
}
```

### wc_sessionPing

```jsonc
// wc_sessionPing params
{
  // empty
}
```

### wc_sessionRequest

Sends a CAIP-27 request to the peer client. The client should immediately reject the request and respond an error if the target session permissions doesn't include the requested method or chain ID.

```jsonc
// wc_sessionRequest params
{
  "request": {
    "method": string,
    "params": any
  },
  "chainId": string
}
```

### wc_sessionEvent

```jsonc
// wc_sessionEvent params
{
  "event": {
    "name": string,
    "data": any
  },
  "chainId": string
}
```
