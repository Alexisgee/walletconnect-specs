# Chat Invite

## User Flow

Once A has knowledge of the peer B's public key it can invite into a chat thread and with the following flow initiate a conversation:

1. A sends an invite to B's public key and adds an opening message
2. B receives the chat invite with an opening message
3. B accepts the chat invite and the thread is created
4. A receives notification the chat was accepted and created

Now both A and B can exchange messages in the newly created chat thread

## Invite Protocol

A retrieves the public key associated with B's blockchain account, publicKey X.

A generates a keyPair Y to encrypt the opening message with derived DH symKey I.

A sends invite encrypted with type 1 envelope to the invite topic including publicKey Y.

Invite topic is derived as the hash of the publicKey X.

B decrypts type 1 envelope with the privateKey X and publicKey Y and deriving DH symKey I.

B accepts the invite and generates a keyPair Z for chat thread.

B sends response with publicKey Z on invite topic encrypted with type 0 envelope.

B derives symKey T using publicKey Y and privKey Z.

Thread topic is derived as the hash of the symKey T.

A receives response which includes publicKey Z.

A derives symKey T using privKey Y and publicKey Z.

A and B both subscribe to thread topic and sends messages with symKey T
