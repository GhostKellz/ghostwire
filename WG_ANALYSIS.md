  WireGuard Library Performance Analysis

  Current options:

  1. boringtun (Pure Rust, userspace)
    - ✅ Pure Rust, memory safe
    - ✅ Easy integration
    - ❌ Slower than kernel WireGuard (CPU bound)
    - ❌ May not hit 2.5 Gbps without optimizations
  2. Kernel WireGuard (via wireguard-rs bindings)
    - ✅ Maximum performance (kernel bypass)
    - ✅ SIMD optimizations
    - ❌ Platform-dependent
    - ❌ Requires root/capabilities
  3. Custom optimized userspace (hybrid approach)
    - ✅ SIMD crypto (ChaCha20-Poly1305)
    - ✅ Zero-copy networking
    - ✅ Multi-threaded packet processing
    - ✅ Works with QUIC multiplexing

  For GhostWire, I recommend starting with boringtun for development but planning a
  performance-optimized fork with:

  - SIMD implementations using aes and chacha20poly1305 crates
  - Multi-threaded packet processing
  - Zero-copy integration with QUIC streams
  - Vectorized operations for batch packet processing

  The QUIC multiplexing actually helps WireGuard performance because:
  - Congestion control prevents packet loss that hurts WireGuard
  - Stream prioritization keeps control traffic flowing
  - Connection migration reduces reconnection overhead

  Should I continue building out the configuration system and server entry points? The foundation
  for high-performance QUIC + WireGuard is looking very promising!

  Todos
