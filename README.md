# hsdpsigner

Caddy module to sign HTTP requests

# building

```shell
xcaddy build \
  --with github.com/loafoe/hsdpsigner
  --with github.com/caddy-dns/route53@v1.3.0 \
  --with github.com/gr33nbl00d/caddy-revocation-validator \
  --with github.com/caddyserver/caddy/v2=github.com/caddyserver/caddy/v2@v2.7.6
```

# updating OCI image

The build process is captured in a set of Github Actions. These workflows can be executed
locally with the help of the [act](https://github.com/nektos/act) tool. Install it locally
and then simply run `act`

## secrets

The docker flows require HSP Docker registry credentials. Create a `.secrets` file and add
the following lines

```shell
HSDP_DOCKER_USERNAME=replace-with-registry-username
HSDP_DOCKER_PASSWORD=replace-with-registry-password
```

## updating tagged builds

After tagging the repository you can build and publish new OCI images as follows:


```shell
act -W .github/workflows/docker_tagged.yml
```

# license

License is MIT
