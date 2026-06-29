# syntax=docker/dockerfile:1

# Stage 1: Build the Vue.js frontend
FROM node:25 AS frontend-builder

COPY assets/logo.png /app/assets/logo.png

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: cargo-chef base (shared toolchain + chef install, cached)
FROM rust:1.94 AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app/backend

# Stage 3: plan the dependency graph (recipe changes only when deps change)
FROM chef AS planner
COPY backend/ ./
RUN cargo chef prepare --recipe-path recipe.json

# Stage 4: build dependencies (cached layer), then the application
FROM chef AS backend-builder
ARG RUN_TESTS=false

# Cook only the dependencies — this layer is reused as long as recipe.json
# (i.e. Cargo.toml / Cargo.lock) is unchanged, even when source files change.
COPY --from=planner /app/backend/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/backend/target \
    cargo chef cook --release --recipe-path recipe.json

# Build the actual binary. target/ is a cache mount and is NOT persisted into
# the image layer, so the binary must be copied out within the same RUN.
COPY backend/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/backend/target \
    cargo build --release --locked \
    && cp target/release/backend /app/backend/backend \
    && if [ "$RUN_TESTS" = "true" ]; then \
         cargo test --features test-mode; \
       else \
         echo "Skipping tests"; \
       fi

# Stage 5: Final container with Nginx and backend binary
FROM nginx:stable

WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

EXPOSE 80

CMD ["/bin/sh", "-c", "nginx && /app/bin/backend"]
