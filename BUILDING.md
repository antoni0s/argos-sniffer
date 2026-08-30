# Building Argos Sniffer

Argos Sniffer is written in C and has no runtime dependency on OpenSSL or other external crypto libraries.

The source files are located in `src/`.

## Native Linux build

Full QUIC support:

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
  src/argos-sniffer.c -lm -o argos-sniffer
```

Strict build used by CI:

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
  src/argos-sniffer.c -lm -o argos-sniffer
```

## Minimal build without QUIC parsing

For systems where the QUIC parser is not required:

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
  -DARGOS_QUIC_STUB src/argos-sniffer.c -lm -o argos-sniffer
```

## Static ARM64 build for OpenWrt

The release workflow builds the ARM64 binary inside an ARM64 Alpine Linux environment. This produces a static musl-linked executable suitable for ARM64 OpenWrt routers without requiring additional runtime libraries.

Equivalent local build using Docker:

```sh
mkdir -p dist

docker run --rm --platform linux/arm64 \
  -v "$PWD:/work" -w /work alpine:latest sh -ec '
    apk add --no-cache gcc musl-dev linux-headers
    cc -std=c11 -Os -Wall -Wextra -Wpedantic -Werror \
      -static -ffunction-sections -fdata-sections \
      -Wl,--gc-sections \
      src/argos-sniffer.c -lm \
      -o dist/argos-sniffer-arm64
    strip dist/argos-sniffer-arm64
  '
```

Verify that the result is an ARM64 static executable:

```sh
file dist/argos-sniffer-arm64
readelf -h dist/argos-sniffer-arm64
readelf -l dist/argos-sniffer-arm64
```

A static build should not contain a `Requesting program interpreter` entry.

## UPX-compressed ARM64 build

A second ARM64 artifact is produced with UPX for flash-constrained OpenWrt routers.

Starting from the normal static ARM64 binary:

```sh
cp dist/argos-sniffer-arm64 dist/argos-sniffer-arm64-upx
upx --best --lzma dist/argos-sniffer-arm64-upx
upx -t dist/argos-sniffer-arm64-upx
```

The UPX build reduces storage usage on flash. It is provided alongside the normal uncompressed binary so deployments can choose between minimum flash footprint and an ordinary ELF executable.

## GitHub Actions

`.github/workflows/build-arm64.yml` performs the following checks automatically:

1. Strict native full-QUIC compilation with `-Werror`.
2. Strict QUIC-stub compilation with `-Werror`.
3. Static ARM64/musl build.
4. ELF architecture and static-link verification.
5. UPX compression and UPX integrity test.
6. SHA-256 generation for both ARM64 binaries.
7. Upload of the standard ARM64 binary, UPX ARM64 binary, and `SHA256SUMS` as a workflow artifact.

When a tag matching `v<source-version>` is pushed, the same files are attached to the corresponding GitHub Release. The workflow rejects a release tag when it does not match the `VERSION` defined in `src/argos-sniffer.c`.

## Release artifacts

For version `5.2.1`, the ARM64 artifacts are named:

```text
argos-sniffer-5.2.1-arm64
argos-sniffer-5.2.1-arm64-upx
SHA256SUMS
```
