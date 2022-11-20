# Traefik Cloudflare Access Validator

This is a simple Traefik middleware plugin that validates Cloudflare Access JWT tokens. See the [Cloudflare Access documentation](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/) for more information.


## Configuration

The middleware can be configured with the following options:

| **Setting** | **Type** | **Required** | **Description**                                                                                                                                   |
|-------------|----------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| team_domain | string   | yes          | Cloudflare Access team domain name                                                                                                                |
| policy_aud  | string   | yes          | Application Audience Tag [docs](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/#get-your-aud-tag) |


### Enable the plugin

To enable the plugin, add the following to your Traefik configuration:

```yaml
experimental:
  plugins:
    cloudflare-access-validator:
      moduleName: github.com/Cyb3r-Jak3/traefik-cloudflare-jwt
      version: v0.1.0
```

### Plugin configuration

To configure the plugin, add the following to your Traefik configuration:

```yaml
http:
  middlewares:
    cloudflare-access-validator:
      plugin:
        cloudflare-access-validator:
            team_domain: example
            policy_aud: 1234567890

  routers:
    my-router:
      rule: Path(`/whoami`)
      service: service-whoami
      entryPoints:
        - http
      middlewares:
        - cloudflare-access-validator

  services:
    service-whoami:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
```

## Testing

There are basic tests for making sure missing or invalid tokens are rejected. Due to the dependence on external services, I am unable to test that 