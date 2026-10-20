FROM node:24-alpine AS build

WORKDIR /app
# Empty by default = same-origin: the browser calls /api and /ws on the host
# that served the page, and nginx proxies them to the backend. Only override
# for a split-origin setup (the API on a different host).
ARG VITE_API_BASE_URL=
ARG VITE_WS_BASE_URL=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL} \
    VITE_WS_BASE_URL=${VITE_WS_BASE_URL}

COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Runtime stage: serve the built SPA with nginx, reverse-proxying /api and /ws to
# the backend. Uses nginx:alpine's built-in envsubst-templating entrypoint so the
# backend address is configurable per environment (docker-compose vs Azure
# Container Apps) without baking it into the image — see frontend/nginx.conf.template
# for the full BACKEND_UPSTREAM contract.
FROM nginx:1.27-alpine AS runtime

# Default for docker-compose, where the backend is a separate service reachable by
# its service name. Azure Container Apps runs frontend+backend as sidecars in one
# Container App (shared network namespace), so the Bicep definition MUST override
# this to BACKEND_UPSTREAM=localhost:8000 at deploy time.
ENV BACKEND_UPSTREAM=backend:8000
# Only substitute this one variable — leaves nginx's own $host/$uri/etc. untouched.
ENV NGINX_ENVSUBST_FILTER=BACKEND_UPSTREAM

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Run nginx unprivileged. nginx:alpine ships a non-root `nginx` user already used
# for the worker processes by default config, but the master process still needs
# root to bind privileged ports and write to root-owned paths — since we listen on
# 8080 (unprivileged) we can drop to `nginx` entirely. Repoint the pidfile and temp
# dirs to locations the `nginx` user can write, and hand it ownership of the html
# and nginx runtime directories.
RUN mkdir -p /tmp/client_temp /tmp/proxy_temp /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp \
    && sed -i -E 's#^pid[[:space:]]+[^;]+;#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf \
    && chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /etc/nginx/conf.d /tmp/client_temp /tmp/proxy_temp /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp

USER nginx
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
