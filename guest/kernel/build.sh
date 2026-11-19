#!/usr/bin/env bash
# Builds orbd's pinned QEMU guest kernel: Linux 7.3 stable, everything built in (no modules,
# no initrd), booted with `root=/dev/vda`.
#
#   guest/kernel/build.sh [OUT_DIR]        (default: target/guest-kernel)
#   ARCH=arm64 guest/kernel/build.sh       (default: x86_64; build on a host of that arch)
#
# Outputs in OUT_DIR (IMAGE is bzImage on x86_64, Image on arm64):
#   IMAGE            the kernel (a runtime asset; point the agent's kernel path at it)
#   config           the final .config
#   IMAGE.sha256     sha256 of IMAGE (the kernel digest pinned in checkpoint manifests)
#   manifest.txt     kernel version, source and fragment digests, final config digest
#
# Needs: curl, sha256sum, tar, xz, gcc, make, flex, bison, bc, libelf-dev, libssl-dev.
# Set ORBD_KERNEL_CACHE to reuse the downloaded tarball (default: ~/.cache/orbd-kernel).
set -euo pipefail

KERNEL_VERSION=7.3.5
KERNEL_SHA256=8f293f83d54f0b7b9be56863ebc5e4ea79d73e530b4ae55c572be97ef39f0990
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x/linux-${KERNEL_VERSION}.tar.xz"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$(realpath -m "${1:-$repo/target/guest-kernel}")"
cache="${ORBD_KERNEL_CACHE:-$HOME/.cache/orbd-kernel}"
arch="${ARCH:-x86_64}"
case "$arch" in
x86_64) defconfigs=(x86_64_defconfig kvm_guest.config) image=bzImage image_src=arch/x86/boot/bzImage ;;
arm64) defconfigs=(defconfig) image=Image image_src=arch/arm64/boot/Image ;;
*) echo "unsupported ARCH=$arch (x86_64 or arm64)" >&2; exit 1 ;;
esac
fragment="$here/orbd.config"
arch_fragment="$here/orbd-$arch.config"
tarball="$cache/linux-${KERNEL_VERSION}.tar.xz"
src="$out/build/linux-${KERNEL_VERSION}"

mkdir -p "$cache" "$out/build"

if ! echo "$KERNEL_SHA256  $tarball" | sha256sum -c --status 2>/dev/null; then
    echo "downloading $KERNEL_URL"
    curl -fL --retry 3 -o "$tarball.part" "$KERNEL_URL"
    echo "$KERNEL_SHA256  $tarball.part" | sha256sum -c --quiet
    mv "$tarball.part" "$tarball"
fi

rm -rf "$src"
tar -C "$out/build" -xf "$tarball"

# Reproducible build metadata (no host name, user or wall-clock time in the image).
export KBUILD_BUILD_USER=orbd KBUILD_BUILD_HOST=orbd
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC" KBUILD_BUILD_VERSION=1

for c in "${defconfigs[@]}"; do
    make -C "$src" -s "$c"
done
"$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" "$fragment" "$arch_fragment" >/dev/null
make -C "$src" -s olddefconfig

# Every option in the fragment must have survived dependency resolution.
missing=0
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=*)
            if ! grep -qxF "$line" "$src/.config"; then
                echo "config: wanted $line, got: $(grep -E "^(# )?${line%%=*}[= ]" "$src/.config" || echo unset)" >&2
                missing=1
            fi
            ;;
        "# CONFIG_"*" is not set")
            sym="${line#\# }"
            sym="${sym%% *}"
            if grep -qE "^${sym}=" "$src/.config"; then
                echo "config: wanted $sym unset, got: $(grep -E "^${sym}=" "$src/.config")" >&2
                missing=1
            fi
            ;;
    esac
done < <(cat "$fragment" "$arch_fragment")
[ "$missing" = 0 ] || { echo "config fragment not satisfied" >&2; exit 1; }

make -C "$src" -s -j"$(nproc)" "$image"

cp "$src/$image_src" "$out/$image.tmp"
cp "$src/.config" "$out/config"
mv -f "$out/$image.tmp" "$out/$image"
kernel_sha="$(sha256sum "$out/$image" | cut -d' ' -f1)"
echo "$kernel_sha  $image" >"$out/$image.sha256"
cat >"$out/manifest.txt" <<EOF
arch=${arch}
kernel_version=${KERNEL_VERSION}
kernel_release=$(make -C "$src" -s kernelrelease)
source_url=${KERNEL_URL}
source_sha256=${KERNEL_SHA256}
fragment_sha256=$(sha256sum "$fragment" | cut -d' ' -f1)
arch_fragment_sha256=$(sha256sum "$arch_fragment" | cut -d' ' -f1)
config_sha256=$(sha256sum "$out/config" | cut -d' ' -f1)
${image}_sha256=${kernel_sha}
EOF
cat "$out/manifest.txt"
