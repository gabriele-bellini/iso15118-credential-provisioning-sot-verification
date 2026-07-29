# === Stage 1: Build Stage
FROM debian:bookworm-slim AS builder

# Install build tools, pkg-config, and GTK2 development libraries required by OPAM
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libgtk2.0-dev \
    libexpat1-dev \
    opam \
    m4 \
    ca-certificates \
    patch \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Initialize OPAM and compile ProVerif
RUN opam init --disable-sandboxing -y \
    && eval $(opam env) \
    && opam install -y proverif.2.05


    
    
    
    
    
# === Stage 2: Runtime Stage
FROM debian:bookworm-slim AS runner

# Install runtime dependencies (including GTK2 shared libraries for proverif_interact)
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    time \
    ca-certificates \
    libgtk2.0-0 \
    libexpat1 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled ProVerif binaries into PATH
COPY --from=builder /root/.opam/default/bin/proverif* /usr/local/bin/

WORKDIR /artefact

CMD ["proverif", "--help"]
