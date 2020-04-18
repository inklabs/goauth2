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

## Docker

```
docker run -p 8080:8080 inklabs/goauth2
```

## Client Credentials Grant

http://tools.ietf.org/html/rfc6749#section-4.4

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

http://tools.ietf.org/html/rfc6749#section-4.3

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
    -d "password=p45w0rd" \
    -d "scope=read_write"
```

```json
{
  "access_token": "a3c5300be4d24e65a68176c7ba521c50",
  "expires_at": 1574371565,
  "token_type": "Bearer",
  "scope": "read_write",
  "refresh_token": "8fc94d5d75cc4ddd9bc6b5d13ebed390"
}
```
