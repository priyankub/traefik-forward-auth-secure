# Examples

Working setups for Traefik v3. Replace `example.com` with your own domain throughout.

| Example | Auth applied | Provider | Mode |
|---|---|---|---|
| [docker-compose/docker-compose.yml](docker-compose/docker-compose.yml) | Selected routers | Google | Overlay |
| [docker-compose/docker-compose-oidc.yml](docker-compose/docker-compose-oidc.yml) | Selected routers | OpenID Connect | Overlay |
| [docker-compose/docker-compose-auth-host.yml](docker-compose/docker-compose-auth-host.yml) | Every router (entrypoint) | Google | Auth Host |
| [kubernetes/simple](kubernetes/simple/) | Selected IngressRoutes | Google | Overlay |
| [kubernetes/advanced](kubernetes/advanced/) | Selected IngressRoutes | Google | Auth Host, with rules |

See the main [README](../README.md#operation-modes) for how Overlay and Auth Host modes differ.

## Docker Compose

```bash
cd docker-compose
cp .env.example .env    # then fill it in
docker compose up -d                                   # or
docker compose -f docker-compose-auth-host.yml up -d
```

Ports 80 and 443 must be reachable from the internet for Let's Encrypt, and your DNS names must point at the host.

A few choices in these files are deliberate:

- **The middleware is declared in [dynamic.yml](docker-compose/dynamic.yml), not as labels on the auth container.** In Traefik, any container with labels gets a router, which would make the auth service reachable from outside. Without labels it's only reachable over the Docker network. The Auth Host example is the exception: the auth host needs a router.
- **`exposedByDefault=false`**: only containers with `traefik.enable=true` are routed.
- **The auth container runs as `nobody`, with a read-only filesystem and no capabilities.** It needs nothing more.
- **The image has no shell**, so there's no Docker `healthcheck`. In Kubernetes the kubelet probes `/ping` directly.

To protect another app, give its router the middleware:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.myapp.rule=Host(`myapp.example.com`)
  - traefik.http.routers.myapp.entrypoints=websecure
  - traefik.http.routers.myapp.middlewares=forward-auth@file
```

## Kubernetes

These assume Traefik v3 is already installed, for example with the official [Helm chart](https://github.com/traefik/traefik-helm-chart), which also installs the `traefik.io` CRDs.

```bash
# Simple
kubectl apply -f kubernetes/simple/

# Advanced (kustomize)
cp kubernetes/advanced/traefik-forward-auth/secrets/traefik-forward-auth.env.example \
   kubernetes/advanced/traefik-forward-auth/secrets/traefik-forward-auth.env   # then fill it in
kubectl apply -k kubernetes/advanced/
```

To protect another app, add the middleware to its IngressRoute:

```yaml
    middlewares:
    - name: traefik-forward-auth
```

A Middleware can only be used by IngressRoutes in its own namespace, unless Traefik runs with `providers.kubernetesCRD.allowCrossNamespace=true`. In that case refer to it as `name: traefik-forward-auth` plus `namespace: <its namespace>`.

To protect everything (global authentication), attach the middleware to the entrypoint in the Helm values instead:

```yaml
ports:
  websecure:
    middlewares:
    - default-traefik-forward-auth@kubernetescrd   # <namespace>-<name>@kubernetescrd
```
