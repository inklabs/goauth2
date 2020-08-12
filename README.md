# Go OAuth2 Server

[![Build Status](https://travis-ci.org/inklabs/goauth2.svg?branch=master)](https://travis-ci.org/inklabs/goauth2)
[![Go Report Card](https://goreportcard.com/badge/github.com/inklabs/goauth2)](https://goreportcard.com/report/github.com/inklabs/goauth2)
[![Test Coverage](https://api.codeclimate.com/v1/badges/7970cb8ab9408b433cde/test_coverage)](https://codeclimate.com/github/inklabs/goauth2/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/7970cb8ab9408b433cde/maintainability)](https://codeclimate.com/github/inklabs/goauth2/maintainability)
[![GoDoc](https://godoc.org/github.com/inklabs/goauth2?status.svg)](https://godoc.org/github.com/inklabs/goauth2)
[![Go Version](https://img.shields.io/github/go-mod/go-version/inklabs/goauth2.svg)](https://github.com/inklabs/goauth2/blob/master/go.mod)
[![Release](https://img.shields.io/github/release/inklabs/goauth2.svg?include_prereleases&sort=semver)](https://github.com/inklabs/goauth2/releases/latest)
[![License](https://img.shields.io/github/license/inklabs/goauth2.svg)](https://github.com/inklabs/goauth2/blob/master/LICENSE)

An OAuth2 server in Go. This project uses an embedded [RangeDB](https://www.github.com/inklabs/rangedb) event store.

## Docs

- [Docs](https://github.com/inklabs/rangedb/tree/master/docs)

## Docker

```
docker run -p 8080:8080 inklabs/goauth2
```

## Client Credentials Grant

* https://tools.ietf.org/html/rfc6749#section-4.4

```
+---------+                                  +---------------+
|         |                                  |               |
|         |>--(A)- Client Authentication --->| Authorization |
| Client  |                                  |     Server    |
|         |<--(B)---- Access Token ---------<|               |
|         |                                  |               |
+---------+                                  +---------------+
```

```shell script
curl localhost:8080/token \
    -u client_id_hash:client_secret_hash \
    -d "grant_type=client_credentials" \
    -d "scope=read_write"
```

```json
{
  "access_token": "d5f4985587ea46028c0946e4a240a9c1",
  "expires_at": 1574371565,
  "token_type": "Bearer",
  "scope": "read_write"
}
```

## Resource Owner Password Credentials

* https://tools.ietf.org/html/rfc6749#section-4.3

```
+----------+
| Resource |
|  Owner   |
|          |
+----------+
     v
     |    Resource Owner
     (A) Password Credentials
     |
     v
+---------+                                  +---------------+
|         |>--(B)---- Resource Owner ------->|               |
|         |         Password Credentials     | Authorization |
| Client  |                                  |     Server    |
|         |<--(C)---- Access Token ---------<|               |
|         |    (w/ Optional Refresh Token)   |               |
+---------+                                  +---------------+
```

```shell script
curl localhost:8080/token \
    -u client_id_hash:client_secret_hash \
    -d "grant_type=password" \
    -d "username=john@example.com" \
    -d "password=Pass123!" \
    -d "scope=read_write"
```

```json
{
  "access_token": "a3c5300be4d24e65a68176c7ba521c50",
  "expires_at": 1574371565,
  "token_type": "Bearer",
  "scope": "read_write",
  "refresh_token": "3a801b1fc3d847599b3d5719d82bca7b"
}
```

## Refresh Token

* https://tools.ietf.org/html/rfc6749#section-1.5
* https://tools.ietf.org/html/rfc6749#section-6

```
+--------+                                           +---------------+
|        |--(A)------- Authorization Grant --------->|               |
|        |                                           |               |
|        |<-(B)----------- Access Token -------------|               |
|        |               & Refresh Token             |               |
|        |                                           |               |
|        |                            +----------+   |               |
|        |--(C)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(D)- Protected Resource --| Resource |   | Authorization |
| Client |                            |  Server  |   |     Server    |
|        |--(E)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(F)- Invalid Token Error -|          |   |               |
|        |                            +----------+   |               |
|        |                                           |               |
|        |--(G)----------- Refresh Token ----------->|               |
|        |                                           |               |
|        |<-(H)----------- Access Token -------------|               |
+--------+           & Optional Refresh Token        +---------------+
```

```shell script
curl localhost:8080/token \
    -u client_id_hash:client_secret_hash \
    -d "grant_type=refresh_token" \
    -d "refresh_token=3a801b1fc3d847599b3d5719d82bca7b"
```

```json
{
  "access_token": "97ed11d0d399454eb5ab2cab8b29f600",
  "expires_at": 1574371565,
  "token_type": "Bearer",
  "scope": "read_write",
  "refresh_token": "b4c69a71124641739f6a83b786b332d3"
}
```

## Authorization Code

* https://tools.ietf.org/html/rfc6749#section-4.1

```
+----------+
| Resource |
|   Owner  |
|          |
+----------+
     ^
     |
    (B)
+----|-----+          Client Identifier      +---------------+
|         -+----(A)-- & Redirection URI ---->|               |
|  User-   |                                 | Authorization |
|  Agent  -+----(B)-- User authenticates --->|     Server    |
|          |                                 |               |
|         -+----(C)-- Authorization Code ---<|               |
+-|----|---+                                 +---------------+
  |    |                                         ^      v
 (A)  (C)                                        |      |
  |    |                                         |      |
  ^    v                                         |      |
+---------+                                      |      |
|         |>---(D)-- Authorization Code ---------'      |
|  Client |          & Redirection URI                  |
|         |                                             |
|         |<---(E)----- Access Token -------------------'
+---------+       (w/ Optional Refresh Token)
```

```
open http://localhost:8080/authorize?client_id=client_id_hash&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback&response_type=code&state=somestate&scope=read_write
```

1. Login via the web form (john@example.com | Pass123!)
1. Click button to grant access
1. The authorization server redirects back to the redirection URI including an authorization code and any
   state provided by the client

```
https://example.com/oauth2/callback?code=36e2807ee1f94252ac2d9b1d3adf2ba2&state=somestate
```

```shell script
curl localhost:8080/token \
    -u client_id_hash:client_secret_hash \
    -d "grant_type=authorization_code" \
    -d "code=36e2807ee1f94252ac2d9b1d3adf2ba2" \
    -d "redirect_uri=https://example.com/oauth2/callback"
```

```json
{
  "access_token": "865382b944024b2394167d519fa80cba",
  "expires_at": 1574371565,
  "token_type": "Bearer",
  "scope": "read_write",
  "refresh_token": "48403032170e46e8af72b7cca1612b43"
}
```

## Implicit

* http://tools.ietf.org/html/rfc6749#section-4.2

```
+----------+
| Resource |
|  Owner   |
|          |
+----------+
     ^
     |
    (B)
+----|-----+          Client Identifier     +---------------+
|         -+----(A)-- & Redirection URI --->|               |
|  User-   |                                | Authorization |
|  Agent  -|----(B)-- User authenticates -->|     Server    |
|          |                                |               |
|          |<---(C)--- Redirection URI ----<|               |
|          |          with Access Token     +---------------+
|          |            in Fragment
|          |                                +---------------+
|          |----(D)--- Redirection URI ---->|   Web-Hosted  |
|          |          without Fragment      |     Client    |
|          |                                |    Resource   |
|     (F)  |<---(E)------- Script ---------<|               |
|          |                                +---------------+
+-|--------+
  |    |
 (A)  (G) Access Token
  |    |
  ^    v
+---------+
|         |
|  Client |
|         |
+---------+
```

```
open http://localhost:8080/authorize?client_id=client_id_hash&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback&response_type=token&state=somestate&scope=read_write
```

1. Login via the web form (john@example.com | Pass123!)
1. Click button to grant access
1. The authorization server redirects back to the redirection URI including an access token and any
   state provided by the client in the URI fragment

```
https://example.com/oauth2/callback#access_token=1e21103279e549779a9b5c07d50e641d&expires_at=1574371565&scope=read_write&state=somestate&token_type=Bearer
```
