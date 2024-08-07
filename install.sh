#!/bin/sh

# Pallium install script

# This script will attempt to automatically detect the package manager, perform a system upgrade and install the
# required dependencies.

# Base URL for binaries. Must not end with a slash.
BASE_URL="https://github.com/blechschmidt/pallium/releases/latest/download"

echo 'Pallium Installation Script'

OPTS=$(getopt -o '' --long "dependencies-only,noconfirm,test-dependencies,no-dependencies,binary" -- "$@")

eval set -- "$OPTS"

CONFIRM=1
FROM_SOURCE=1

while true; do
  case "$1" in
    --dependencies-only) DEPENDENCIES_ONLY=1; shift;;
    --no-dependencies) NO_DEPENDENCIES=1; shift;;
    --test-dependencies) TEST_DEPENDENCIES=1; shift;;  # Install dependencies required for tests. Not in use yet.
    --noconfirm) CONFIRM=0; shift;;
    --binary) FROM_SOURCE=0; shift;;  # Whether to install from source
    --) shift; break;;
    *) echo "Error."; exit 1;;
  esac
done

contains() { case "$1" in *"$2"*) true ;; *) false ;; esac }

# shellcheck disable=SC2039
is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

get_goarch() {
  # https://github.com/golang/go/blob/016d7552138077741a9c3fdadc73c0179f5d3ff7/src/cmd/dist/main.go#L94
  OUT=$(uname -m)
  OUT_ALL=$(uname -r)
  export RESULT

  if contains "$OUT_ALL" "RELEASE_ARM64"; then
    RESULT="arm64"
  elif contains "$OUT" "x86_64" || contains "$OUT" "amd64"; then
    RESULT="amd64"
  elif contains "$OUT" "86"; then
    RESULT="386"
    # Darwin case ignored
  elif contains "$OUT" "aarch64" || contains "$OUT" "arm64"; then
    RESULT="arm64"
  elif contains "$OUT" "arm"; then
    RESULT="arm"
    # NetBSD case ignored
  elif contains "$OUT" "ppc64le"; then
    RESULT="ppc64le"
  elif contains "$OUT" "ppc64"; then
    RESULT="ppc64"
  elif contains "$OUT" "mips64"; then
    RESULT="mips64"
    LE=$(python3 -c "import sys;sys.exit(int(sys.byteorder=='little'))")
    test "$LE" = "1" && RESULT="mips64le"
  elif contains "$OUT" "mips"; then
    RESULT="mips"
    LE=$(python3 -c "import sys;sys.exit(int(sys.byteorder=='little'))")
    test "$LE" = "1" && RESULT="mipsle"
  elif contains "$OUT" "loongarch64"; then
    RESULT="loong64"
  elif contains "$OUT" "riscv64"; then
    RESULT="riscv64"
  elif contains "$OUT" "s390x"; then
    RESULT="s390x"
  fi
}

download_file() {
  # This breaks if the arguments contain quotes
  SRC="$1"
  DST="$2"
  if command -v wget >/dev/null 2>&1; then
    wget -O- "$SRC" > "$DST"
  elif command -v curl >/dev/null 2>&1; then
    curl "$SRC" > "$DST"
  else
    echo "curl or wget are required. Aborting."
    exit 1
  fi
}

install_binary() {
  get_goarch
  ARCH="$RESULT"
  DOWNLOAD_URL="$BASE_URL/pallium-x86_64-bundle-linux"
  DST_DIR=~/".local/share/applications"
  is_root && {
    DST_DIR="/usr/local/bin"
  }
  DST_FILENAME="pallium"

  # If stdout is a terminal.
  test -t 1 && {
    printf "Installation directory [Default: %s]: " "$DST_DIR" >&2
    read -r OVERRIDDEN_DST_DIR
  }

  test -z "$OVERRIDDEN_DST_DIR" || {
    DST_DIR="$OVERRIDDEN_DST_DIR"
  }

  DST_PATH="$DST_DIR/$DST_FILENAME"
  mkdir -p "$DST_DIR"
  download_file "$DOWNLOAD_URL" "$DST_PATH"
  chmod a+x "$DST_PATH"
}

test "$FROM_SOURCE" != "1" && {
  install_binary
  exit 0
}

test "$(id -u)" -eq 0 || {
  echo "You must be root."
  exit 1
}

cd "$(dirname "$0")" || (echo "Failed to change directory"; exit 1)

# Alpine Linux
if command -v apk >/dev/null 2>&1; then
  PKGMGR=apk
  UPDATE="$PKGMGR update; $PKGMGR upgrade"
  INSTALL="$PKGMGR add"
fi

# Fedora, CentOS
if command -v yum >/dev/null 2>&1; then
  PKGMGR=yum
  INSTALL="$PKGMGR install -y"
fi

# Fedora, CentOS
if command -v dnf >/dev/null 2>&1; then
  PKGMGR=dnf
  INSTALL="$PKGMGR install -y"
fi

# Debian and Ubuntu
if command -v apt >/dev/null 2>&1; then
  PKGMGR=apt
  UPDATE="$PKGMGR update"
  INSTALL="$PKGMGR install -y"
fi

# Debian and Ubuntu
if command -v apt-get >/dev/null 2>&1; then
  PKGMGR=apt-get
  INSTALL="$PKGMGR install -y"
fi

# Arch Linux
if command -v pacman >/dev/null 2>&1; then
  PKGMGR=pacman
  UPDATE="pacman -Syyu --noconfirm"
  INSTALL="$PKGMGR -S --noconfirm"
fi

# openSUSE
if command -v zypper >/dev/null 2>&1; then
  PKGMGR=zypper
  UPDATE="zypper refresh"
  INSTALL="$PKGMGR -n install"
fi

test "$PKGMGR" != "" || (echo "Failed to determine package manager"; exit 1)

echo "Detected package manager: $PKGMGR"

ask_continue() {
  echo "$1"
  test "$CONFIRM" = "1" && {
    printf "Do you want to continue? (y/n) "
    read -r choice
    case "$choice" in
      y|Y ) ;;
      * ) exit 1;;
    esac
  }
}

install_pkg() {
  ask_continue "\"$1\" will be installed using \"$INSTALL $1\"."
  $INSTALL "$1"
}

test "$UPDATE" != "" && {
  ask_continue "Your system will be updated using \"$UPDATE\"."
  eval "$UPDATE"
}

install_python() {
  command -v python3 >/dev/null 2>&1
  test $? -eq 0 || install_pkg python3
}

install_pip() {
  python3 -m pip >/dev/null 2>&1
  test $? -eq 0 || {
    if [ "$PKGMGR" = "pacman" ]; then
      install_pkg python-pip
    elif [ "$PKGMGR" = "apk" ]; then
      install_pkg py3-pip
    else
      install_pkg python3-pip
    fi
  }
}

install_setuptools() {
  python3 -m pip install setuptools
}

install_pallium_profiles() {
  mkdir -p /etc/pallium/profiles
  install -m 0600 extra/profiles/tor.json /etc/pallium/profiles/tor.json
}

install_pallium() {
  install_python
  install_pip
  install_setuptools
  python3 -m pip install .
}

install_tor() {
  command -v tor >/dev/null 2>&1
  test $? -eq 0 || {
    # https://support.torproject.org/rpm/
    if [ "$PKGMGR" = "dnf" ]; then
      install_pkg epel-release
    fi
    install_pkg tor
  }
}

install_unzip() {
  command -v unzip >/dev/null 2>&1
  test $? -eq 0 || install_pkg unzip
}

install_curl() {
  command -v curl >/dev/null 2>&1
  test $? -eq 0 || install_pkg curl
}

install_slirp4netns() {
  command -v slirp4netns >/dev/null 2>&1
  test $? -eq 0 || install_pkg slirp4netns
}

install_slirpnetstack() {
  command -v slirpnetstack >/dev/null 2>&1
  { test $? -eq 0 || test -f /usr/local/bin/slirpnetstack; } && return
  get_goarch
  SUFFIX="$RESULT"
  URL=https://github.com/tun2proxy/slirpnetstack/releases/latest/download/slirpnetstack-linux-"$SUFFIX"

  ask_continue "$URL will be downloaded and extracted to /usr/local/bin/."
  curl -L "$URL" > /usr/local/bin/slirpnetstack
  chmod 755 /usr/local/bin/slirpnetstack
}

install_tun2socks() {
  command -v tun2socks >/dev/null 2>&1
  { test $? -eq 0 || test -f /usr/local/bin/tun2socks; } && return
  get_goarch
  SUFFIX="$RESULT"
  test "$SUFFIX" = "arm" && SUFFIX=armv5
  { test "$SUFFIX" = "mipsle" || test "$SUFFIX" = "mips"; } && test -d "/lib/arm-linux-gnueabihf" && SUFFIX="$SUFFIX-hardfloat"

  install_curl

  TMP=$(mktemp -d)
  URL=https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-"$SUFFIX".zip
  ask_continue "$URL will be downloaded and extracted to /usr/local/bin/."
  curl -L "$URL" >"$TMP/tun2socks.zip"
  install_unzip
  unzip -d "$TMP" "$TMP/tun2socks.zip" tun2socks-linux-"$SUFFIX"
  install -m 0755 "$TMP/tun2socks-linux-$SUFFIX" /usr/local/bin/tun2socks
  rm -r "$TMP"
}

install_gvisor() {
  command -v runsc >/dev/null 2>&1
  { test $? -eq 0 || test -f /usr/local/bin/runsc; } && return
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  ask_continue "$URL/runsc will be downloaded and extracted to /usr/local/bin/."
  # https://gvisor.dev/docs/user_guide/install/
  (
    WD="$(pwd)"
    TMP=$(mktemp -d)
    cd "$TMP"
    set -e
    wget "${URL}"/runsc "${URL}"/runsc.sha512 \
      "${URL}"/containerd-shim-runsc-v1 "${URL}"/containerd-shim-runsc-v1.sha512
    sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
    rm -f -- *.sha512
    chmod a+rx runsc containerd-shim-runsc-v1
    mv runsc containerd-shim-runsc-v1 /usr/local/bin
    cd "$WD"
    rm -r "$TMP"
  )
}

test "$DEPENDENCIES_ONLY" = "1" || {
  install_pallium
  install_pallium_profiles
}

test "$NO_DEPENDENCIES" != "1" && {
  install_tor
  install_tun2socks
  install_slirpnetstack
  install_gvisor
}
