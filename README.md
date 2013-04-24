pqAuth
======

Web API Authentication with SSH Public Keys


## Protocol Overview

pqAuth is an implementation of the [Needham-Schroeder-Lowe Public-Key Protocol](http://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol) over HTTP. Using pqAuth, Web APIs and their clients can authenticate eachother using SSH keys, and agree on a *session key*, a temporary authentication token that the client sends along with API requests.

A pqAuth authentication handshake has four steps:

### 1. Client sends random GUID to the server
```javascript
// encrypted with server's public key
{
  client_guid: "6304fb3e-68ed-4e59-bfd5-ab03ebc15762",
  client_public_key_fingerprint: "df:ab:ec:d1:66:ef:32:df:ab:62:d3:4a:0d:f3:f4:28"
}
```


### 2. Server sends a random GUID back to the client
```javascript
// encrypted with client's public key
{
  client_guid: "6304fb3e-68ed-4e59-bfd5-ab03ebc15762",
  server_guid: "097e21da-2aa9-40d8-9872-8c9698f91e9c",
  session_key_timeout: 1366761788, // optional, session key timeout timestamp
  server_public_key_fingerprint: "46:2b:54:17:2a:28:d0:55:57:2e:68:37:35:b3:6d:a7"
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
session_key = client_guid + server_guid
```

After this, the client must include `session_key` in every API call. pqAuth does not specify how `session_key` must be included in subsequent requests, that is API implementation specific.

Some API providers want `session_key` to be attached as a request variable (`https://api.provider.com/call?session_key=xxx`), some want it as an HTTP header (`X-Session-Key: xxx`), still others may want it as an HMAC signature somewhere. The point is, pqAuth is designed to integrate with existing APIs, only providing an authentication method.
