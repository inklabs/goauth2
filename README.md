# Go OAuth2 Server

[![Build Status](https://travis-ci.org/inklabs/goauth2.svg?branch=master)](https://travis-ci.org/inklabs/goauth2)
[![Go Report Card](https://goreportcard.com/badge/github.com/inklabs/goauth2)](https://goreportcard.com/report/github.com/inklabs/goauth2)
[![GoDoc](https://godoc.org/github.com/inklabs/goauth2?status.svg)](https://godoc.org/github.com/inklabs/goauth2)
[![Go Version](https://img.shields.io/github/go-mod/go-version/inklabs/goauth2.svg)](https://github.com/inklabs/goauth2/blob/master/go.mod)
[![Release](https://img.shields.io/github/release/inklabs/goauth2.svg?include_prereleases&sort=semver)](https://github.com/inklabs/goauth2/releases/latest)
[![License](https://img.shields.io/github/license/inklabs/goauth2.svg)](https://github.com/inklabs/goauth2/blob/master/LICENSE)

An OAuth2 server in Go. This project uses an embedded [RangeDB](https://www.github.com/inklabs/rangedb) event store.

## Docker

```
docker run -p 8080:8080 inklabs/goauth2
```
