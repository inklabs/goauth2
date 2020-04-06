# GOAuth2 Docker

Docker container automated builds: https://hub.docker.com/r/inklabs/goauth2

## Building Locally

### Build Image

```
docker build -f build/Dockerfile -t inklabs/goauth2:local .
```

### Run Container

```
docker run -p 8080:8080 inklabs/goauth2:local
```
