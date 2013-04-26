pqAuth
======

Web API Authentication with SSH Public Keys


## The Basics in Python

```python
# On the client

from pqauth import crypto
from pqauth.client import ClientAuthenticator

# Load the RSA keys, optionally decrypting them if they are encrypted
client_key = crypto.load_key_file("/path/to/id_rsa", password="bosco")
server_public_key = crypto.load_key_file("/path/to/server/id_rsa.pub")

# paAuth endpoints on the API server
server_hello_url = "https://api.example.com/pqauth/hello"
server_confirm_url = "https://api.example.com/pqauth/confirm"

authenticator = ClientAuthenticator(client_key, server_public_key,
                                    server_hello_url, server_confirm_url)

# A string to use as the auth token for further requests
# The server knows the same session_key.
session_key = authenticator.authenticate()

```

I'm still working on the server-side part, but look at the Django example.

## Protocol Overview

pqAuth is an implementation of the [Needham-Schroeder-Lowe Public-Key Protocol](http://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol) over HTTP. Using pqAuth, Web APIs and their clients can authenticate eachother using SSH keys, and agree on a *session key*, a temporary authentication token that the client sends along with API requests.

A pqAuth authentication handshake has four steps:

### 1. Client sends random GUID to the server
```javascript
// encrypted with server's public key
{
  client_guid: "6304fb3e-68ed-4e59-bfd5-ab03ebc15762",
  client_key_fingerprint: "df:ab:ec:d1:66:ef:32:df:ab:62:d3:4a:0d:f3:f4:28"
}
```


### 2. Server sends a random GUID back to the client
```javascript
// encrypted with client's public key
{
  client_guid: "6304fb3e-68ed-4e59-bfd5-ab03ebc15762",
  server_guid: "097e21da-2aa9-40d8-9872-8c9698f91e9c",
  expires: 1366761788, // optional, session key timeout timestamp
  server_key_fingerprint: "46:2b:54:17:2a:28:d0:55:57:2e:68:37:35:b3:6d:a7"
}
```

### 3. Client sends the server GUID back to the server
```javascript
// encrypted with server's public key
{
  server_guid: "097e21da-2aa9-40d8-9872-8c9698f91e9c",
}
```

### 4. Client and server create the session key

```javascript
// string-concatenate the GUIDs
// this is your client credential
session_key = client_guid + ":" + server_guid
```


### Things that are Good to Know

  - The client must include `session_key` in every subsequent API call, but **how** that's done is implementation-specific. (URL parameter, HTTP header, part of an HMAC signature, whatever)
  - If the server specified `expires`, the client and server need to do this dance again when the `session_key` expires.
  - **Do everything over HTTPS**, if you're not already. While it's safe to do this authentication dance over an insecure channel like HTTP, the `session_key` is a secret, and probably isn't protected in-transit after this authentication dance. But I'm just a developer, I'm not your Dad. Do whatever you want.


## Comparison to SSL Client Authentication

*"But isn't this what SSL Client Certificates do? And pqAuth doesn't even use a certificate authority!"*


Yes, this is sort of what SSL client certificates do, but there are e pretty serious problems with SSL client certificates:

  - **They are nearly impossible to use.** Seriously. Try it some time, it will make you want to stab yourself in the eyeball with a soldering iron. And then, get your load balancer or HTTP server to pass the client identity information along to the app. It's brutal.
  - **You can't extract a session key.** After the SSL/TLS negotiation is done, the client and server share a secret, but this is at the transport layer, and you can't really get at it from the application layer.
  - **You need a certificate authority to sign client certificates.** On its face, this isn't a bad thing, after all, if Verisign says your client is who he says he is, believe it, right? But good luck getting client certs actually signed by CAs. Sure, you could start up your own CA to sign your client certs, but at that point, you're just using a CA to satisfy SSL's bureaucracy instead of as an actual source of trust.

SSL client authentication is well intentioned, but the implementation is a disaster.
