# React + TypeScript + Vite with Docker & nginx

A React application with Docker containers for development and production environments, featuring nginx reverse proxy with SSL certificates.

## Quick Start

### Development Mode

```bash
docker compose --profile dev up
```

Access at: http://localhost:5173

### Production Mode

```bash
docker compose up
```

Access at: https://localhost:5173 (or http://localhost:5174 → redirects to HTTPS)

## Docker Setup Guide

### Files Overview

#### `compose.yml` - Docker Compose Configuration

```yaml
services:
  app-prod: # Production service
    build:
      dockerfile: Dockerfile.prod
    ports:
      - "5173:443" # HTTPS: host:5173 → container:443
      - "5174:80" # HTTP: host:5174 → container:80 (redirects to HTTPS)

  app-dev: # Development service
    profiles: ["dev"] # Only runs with --profile dev
    build: . # Uses regular Dockerfile
    ports:
      - "5173:5173" # Direct port mapping for dev server
```

**Key Points:**

- **Production** (default): Serves built static files via nginx with SSL
- **Development**: Runs Node.js dev server directly
- **Port 5173**: HTTPS access to your app
- **Port 5174**: HTTP access (automatically redirects to HTTPS)

#### `Dockerfile` - Development Container

```dockerfile
FROM node:alpine           # Lightweight Node.js image
WORKDIR /home/app         # Set working directory
COPY package.json .       # Copy package file
RUN npm install -g pnpm   # Install pnpm package manager
RUN pnpm install          # Install dependencies
COPY . .                  # Copy all source code
EXPOSE 5173              # Expose dev server port
CMD ["pnpm", "run", "dev"] # Start development server
```

**Purpose**: Runs your app in development mode with hot reloading.

#### `Dockerfile.prod` - Production Container

```dockerfile
# Build stage - Compile the application
FROM node:alpine AS builder
WORKDIR /home/app
COPY package.json .
RUN npm install -g pnpm
RUN pnpm install
COPY . .
RUN pnpm run build        # Build static files

# Production stage - Serve with nginx
FROM nginx:alpine
COPY --from=builder /home/app/dist /usr/share/nginx/html  # Copy built files
COPY nginx.conf /etc/nginx/nginx.conf                    # Custom nginx config
COPY ssl-certs/ /etc/nginx/ssl-certs/                   # SSL certificates
EXPOSE 80 443            # Expose HTTP and HTTPS ports
CMD ["nginx", "-g", "daemon off;"]                      # Start nginx
```

#### `Dockerfile.prod.secure` - Secure Production Container

```dockerfile
# Build stage - Same as above
FROM node:alpine AS builder
WORKDIR /home/app
COPY package.json .
RUN npm install -g pnpm
RUN pnpm install
COPY . .
RUN pnpm run build

# Secure production stage
FROM nginx:alpine

# Create non-root user for nginx (Security improvement)
RUN addgroup -g 1001 -S nginx-user && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx-user -g nginx-user nginx-user

COPY --from=builder /home/app/dist /usr/share/nginx/html
COPY nginx.prod.conf /etc/nginx/nginx.conf               # Uses secure nginx config

# Copy SSL certificates with strict permissions
COPY ssl-certs/ /etc/nginx/ssl-certs/
RUN chmod 600 /etc/nginx/ssl-certs/nginx-selfsigned.key && \
    chmod 644 /etc/nginx/ssl-certs/nginx-selfsigned.crt && \
    chown -R nginx-user:nginx-user /etc/nginx/ssl-certs/

# Set proper permissions for all nginx files
RUN chown -R nginx-user:nginx-user /usr/share/nginx/html && \
    chown -R nginx-user:nginx-user /var/cache/nginx && \
    chown -R nginx-user:nginx-user /var/log/nginx && \
    chown -R nginx-user:nginx-user /etc/nginx/conf.d

# Remove unnecessary packages to reduce attack surface
RUN apk del --no-cache wget curl

EXPOSE 443               # Only HTTPS port (no HTTP)
USER nginx-user          # Run as non-root user
CMD ["nginx", "-g", "daemon off;"]
```

**Key Concepts:**

- **Multi-stage build**: First stage builds the app, second stage serves it
- **nginx:alpine**: Lightweight web server for serving static files
- **SSL certificates**: Copied into container for HTTPS

#### `nginx.conf` - Basic Web Server Configuration

```nginx
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # HTTPS Server Block
    server {
        listen 443 ssl;                                    # Listen for HTTPS
        server_name localhost;
        root /usr/share/nginx/html;                       # Serve files from here
        index index.html;

        # SSL Certificate Configuration
        ssl_certificate /etc/nginx/ssl-certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/nginx/ssl-certs/nginx-selfsigned.key;

        # Serve static files
        location / {
            try_files $uri $uri/ /index.html;            # SPA fallback
        }

        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # HTTP Server Block (Redirect to HTTPS)
    server {
        listen 80;                                        # Listen for HTTP
        server_name localhost;

        # Redirect all HTTP to HTTPS
        location / {
            return 301 https://$host:5173$request_uri;    # Redirect to HTTPS port
        }
    }
}
```

#### `nginx.prod.conf` - Secure Production Configuration

```nginx
# Production nginx configuration - HTTPS only, no HTTP redirect
worker_processes auto;                                    # Use all CPU cores

events {
    worker_connections 1024;
    use epoll;                                           # Linux optimization
    multi_accept on;                                     # Accept multiple connections
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Performance optimizations
    sendfile on;                                         # Efficient file serving
    tcp_nopush on;                                       # Send headers in one packet
    tcp_nodelay on;                                      # Don't buffer data-sends
    keepalive_timeout 65;                                # Keep connections alive
    types_hash_max_size 2048;                           # Increase hash table size

    # Security - Hide nginx version from headers
    server_tokens off;

    # Gzip compression to reduce bandwidth
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    # HTTPS Server Block - Production
    server {
        listen 443 ssl http2;                            # HTTPS with HTTP/2 support
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;

        # SSL certificate settings
        ssl_certificate /etc/nginx/ssl-certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/nginx/ssl-certs/nginx-selfsigned.key;

        # SSL Security Configuration (Strong encryption only)
        ssl_protocols TLSv1.2 TLSv1.3;                  # Only secure protocols
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;                   # Let client choose best cipher
        ssl_session_cache shared:SSL:10m;                # Cache SSL sessions
        ssl_session_timeout 10m;                         # Session timeout

        # Security Headers (Protect against common attacks)
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';" always;

        # Serve static files
        location / {
            try_files $uri $uri/ /index.html;            # SPA fallback routing
        }

        # Cache static assets with security headers
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;                                   # Cache for 1 year
            add_header Cache-Control "public, immutable";
            # Re-add security headers for cached content
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
        }

        # Security.txt for vulnerability disclosure
        location = /.well-known/security.txt {
            return 200 "Contact: security@example.com\nExpires: 2025-12-31T23:59:59.000Z\nPreferred-Languages: en\n";
            add_header Content-Type text/plain;
        }
    }
}
```

## nginx Basics for Beginners

### What is nginx?

nginx (pronounced "engine-x") is a **web server** - software that receives requests from web browsers and sends back web pages, images, CSS files, etc. Think of it as a digital waiter that takes orders (HTTP requests) and serves the right content back to customers (browsers).

### Key nginx Concepts Explained

#### **Configuration Structure**

nginx configuration is organized in a hierarchical structure:

```
nginx.conf
├── worker_processes (how many CPU cores to use)
├── events { } (connection handling settings)
└── http { } (web server settings)
    └── server { } (virtual host - handles specific domains/ports)
        └── location { } (handles specific URL patterns)
```

#### **Server Blocks**

Think of server blocks as different "virtual websites" running on the same machine:

- Each `server { }` block handles requests for specific domain names or ports
- You can have multiple server blocks (e.g., one for HTTP, one for HTTPS)
- Like having different departments in a store - each handles different types of requests

#### **Location Blocks**

Location blocks define how nginx should handle different URL patterns:

- `location / { }` - handles all URLs starting with `/` (the root)
- `location /images/ { }` - handles URLs like `/images/photo.jpg`
- `location ~* \.(css|js)$ { }` - handles files ending in .css or .js (using regex)

#### **SSL/HTTPS Configuration**

SSL certificates enable encrypted connections (HTTPS):

- `ssl_certificate` - points to the public certificate file (.crt)
- `ssl_certificate_key` - points to the private key file (.key)
- Like having a secure phone line vs. a regular phone call

#### **try_files Directive**

This is crucial for Single Page Applications (SPAs) like React:

```nginx
try_files $uri $uri/ /index.html;
```

**What it does:**

1. Try to serve the exact file requested (`$uri`)
2. If not found, try it as a directory (`$uri/`)
3. If still not found, serve `/index.html` (React app handles routing)

**Why needed:** React apps use "client-side routing" - URLs like `/about` don't correspond to actual files, they're handled by JavaScript.

#### **HTTP Status Codes**

- `200` - OK (file found and served)
- `301` - Permanent redirect (HTTP → HTTPS)
- `404` - Not found
- `500` - Server error

#### **Security Headers Explained**

Our production config includes several security headers:

- **Strict-Transport-Security** - Forces browsers to use HTTPS for 1 year
- **X-Frame-Options: DENY** - Prevents your site from being embedded in iframes (stops clickjacking)
- **X-Content-Type-Options: nosniff** - Prevents browsers from guessing file types (stops MIME sniffing attacks)
- **X-XSS-Protection** - Enables browser's built-in XSS filtering
- **Content-Security-Policy** - Controls what resources (scripts, styles, images) can be loaded

#### **Performance Features**

- **gzip** - Compresses text files before sending (faster loading)
- **expires** - Tells browsers to cache files locally (reduces server load)
- **keepalive_timeout** - Keeps connections open for multiple requests (more efficient)
- **sendfile** - Efficient way to serve static files (bypasses application buffer)

#### **Common nginx Directives**

- `listen 443 ssl` - Listen on port 443 for HTTPS connections
- `server_name localhost` - Respond to requests for "localhost"
- `root /path/to/files` - Directory where website files are stored
- `index index.html` - Default file to serve when accessing a directory
- `return 301 https://...` - Redirect with permanent redirect status
- `add_header` - Add custom HTTP headers to responses

### Configuration Differences Explained

**Basic `nginx.conf`:**

- Simple setup with HTTP redirect to HTTPS
- Minimal security headers
- Basic SSL configuration
- Good for development/testing

**Production `nginx.prod.conf`:**

- HTTPS-only (no HTTP redirect)
- Comprehensive security headers
- Optimized SSL settings (TLS 1.2+, strong ciphers)
- Performance optimizations (gzip, caching)
- Runs as non-root user
- HTTP/2 support for faster loading

## SSL Certificates

Your setup uses self-signed certificates in the `ssl-certs/` directory:

- `nginx-selfsigned.crt` - Certificate file
- `nginx-selfsigned.key` - Private key file

**Note**: Self-signed certificates will show browser warnings but work for development.

## Port Mapping Explained

Docker port mapping format: `"host_port:container_port"`

- `"5173:443"` - Host port 5173 maps to container port 443 (HTTPS)
- `"5174:80"` - Host port 5174 maps to container port 80 (HTTP redirect)

**Why two ports?**

- nginx needs separate ports for HTTP (80) and HTTPS (443)
- HTTP port redirects users to HTTPS for security
- This is standard web server practice

## Understanding the Flow

1. **User visits** http://localhost:5174
2. **Docker routes** to container port 80
3. **nginx HTTP server** receives request
4. **nginx redirects** with 301 status to https://localhost:5173
5. **User's browser** automatically follows redirect
6. **Docker routes** HTTPS to container port 443
7. **nginx HTTPS server** serves the application

## Security Implementation

### Development Setup (compose.yml + nginx.conf)

**Basic security features:**

- SSL with self-signed certificates
- HTTP redirect to HTTPS for convenience
- Basic SSL configuration
- Suitable for local development and testing

### Secure Production Setup (compose.prod.yml + Dockerfile.prod.secure + nginx.prod.conf)

**Enhanced security features implemented:**

#### **Security Headers Added:**

- **Strict-Transport-Security** - Forces HTTPS for 1 year, includes subdomains
- **X-Frame-Options: DENY** - Prevents clickjacking attacks by blocking iframe embedding
- **X-Content-Type-Options: nosniff** - Prevents MIME sniffing attacks
- **X-XSS-Protection** - Enables browser's XSS filtering with blocking mode
- **Referrer-Policy** - Controls referrer information leakage
- **Content-Security-Policy** - Comprehensive policy preventing XSS and injection attacks

#### **SSL/TLS Hardening:**

- **Only TLS 1.2 and 1.3** allowed (blocks vulnerable older protocols)
- **Strong cipher suites only** - ECDHE and DHE with AES-256-GCM
- **HTTP/2 enabled** for better performance and security
- **SSL session caching** for improved efficiency
- **Perfect Forward Secrecy** through ECDHE/DHE key exchange

#### **Container Security:**

- **Non-root user** - nginx runs as `nginx-user` (UID 1001)
- **Strict file permissions** - Private keys (600), certificates (644)
- **Minimal attack surface** - Removed unnecessary packages (wget, curl)
- **HTTPS-only** - No HTTP port exposed (port 80 removed)
- **Proper ownership** - All nginx files owned by nginx-user

#### **Performance & Security Optimizations:**

- **Gzip compression** - Reduces bandwidth and improves loading speed
- **Static asset caching** - 1-year cache with immutable flag
- **Worker process optimization** - Uses all available CPU cores
- **Connection optimizations** - epoll, multi_accept, keepalive
- **Server tokens disabled** - Hides nginx version information

#### **Production Access:**

```bash
# Build and run secure production
docker compose -f compose.prod.yml build --dockerfile Dockerfile.prod.secure
docker compose -f compose.prod.yml up

# Access only via HTTPS (HTTP port not exposed)
https://localhost:5173
```

#### **What's Still Needed for Real Production:**

- **Valid SSL certificates** from trusted CA (Let's Encrypt or commercial)
- **Proper DNS configuration** with your actual domain name
- **Firewall rules** allowing only port 443 (HTTPS)
- **Regular security updates** for base images and packages
- **Log monitoring and alerting** for security events
- **Rate limiting** to prevent abuse
- **Web Application Firewall (WAF)** for additional protection

## Commands

### Development Mode

```bash
# Run development server
docker compose --profile dev up

# Rebuild development
docker compose --profile dev down
docker compose --profile dev build --no-cache
docker compose --profile dev up
```

### Production Mode (Basic)

```bash
# Run production with HTTP redirect
docker compose up

# Rebuild production
docker compose down
docker compose build --no-cache
docker compose up
```

### Production Mode (Secure)

```bash
# Build secure production container
docker compose -f compose.prod.yml build --dockerfile Dockerfile.prod.secure

# Run secure production (HTTPS only)
docker compose -f compose.prod.yml up

# Build and run in one command
docker compose -f compose.prod.yml up --build --dockerfile Dockerfile.prod.secure

# Rebuild secure production from scratch
docker compose -f compose.prod.yml down
docker compose -f compose.prod.yml build --no-cache --dockerfile Dockerfile.prod.secure
docker compose -f compose.prod.yml up
```

**Key differences from basic production:**

- Uses `Dockerfile.prod.secure` instead of `Dockerfile.prod`
- Uses `nginx.prod.conf` with enhanced security
- Only exposes HTTPS port (443), no HTTP
- Runs nginx as non-root user
- Includes comprehensive security headers

### View Logs

```bash
# Development logs
docker compose logs app-dev

# Production logs
docker compose logs app-prod

# Secure production logs
docker compose -f compose.prod.yml logs app-prod
```

### Clean Up

```bash
docker compose down
docker compose -f compose.prod.yml down
docker system prune
```

## Troubleshooting

**Problem**: "Certificate not trusted" browser warning
**Solution**: This is normal with self-signed certificates. Click "Advanced" → "Proceed"

**Problem**: Port already in use
**Solution**: Check what's using the port: `lsof -i :5173`

**Problem**: nginx won't start
**Solution**: Check logs: `docker compose logs app-prod`

**Problem**: Changes not reflected
**Solution**: Rebuild without cache: `docker compose build --no-cache`

---

## Original Vite Template Info

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh
