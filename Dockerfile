# syntax=docker/dockerfile:1
# Single image: builds the React SPA, embeds it into the Go binary, and ships one
# distroless container that serves BOTH the API and the UI on one port (8080).

# ---- stage 1: build the SPA ----
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build   # -> /web/dist

# ---- stage 2: build the Go binary with the SPA embedded ----
FROM golang:1.26 AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# Replace the placeholder SPA with the real build before compiling (go:embed).
RUN rm -rf internal/web/dist
COPY --from=web /web/dist ./internal/web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/transcircle/iam/internal/server.Version=${VERSION}" \
    -o /out/iam ./cmd/iam

# ---- stage 3: runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iam /iam
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/iam"]
CMD ["serve"]
