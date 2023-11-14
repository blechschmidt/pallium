#!/bin/sh

# Build a standalone binary using PyInstaller.
#
# --dist sets up a Docker container for building the project with an old glibc for increased compatibility.
# --install is not to be used manually. It is an entry point for the Docker container only.
# --multiarch uses vagrant, spins up a Ubuntu VM for building pallium for multiple architectures.
# --novirt is to be used with --multiarch. If it is set, building takes place locally instead of inside a VM.
# --bundle causes dependencies like Tor, gvisor, gvisor_init and slirp4netns/slirpnetstack to be bundled with pallium.
#
# Without additional arguments, the script will simply use pyinstaller to build the project, assuming that all
# requirements are met.

# Stop execution upon error.
set -e
# Output commands as they are executed.
set -x

OPTS=$(getopt -o '' --long install,dist,multiarch,novirt,bundle -- "$@")

eval set -- "$OPTS"

while true; do
  case "$1" in
    --install) INSTALL=1; shift;;
    --dist) DIST=1; shift;;
    --multiarch) MULTIARCH=1; shift;;
    --novirt) NOVIRT=1; shift;;
    --bundle) BUNDLE=1; shift;;
    --) shift; break;;
    *) echo "Error."; exit 1;;
  esac
done

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

download_gvisor() {
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  download_file "$URL/runsc" runsc
}

build_gvisor_init() {
  (
    cd ../pallium/gvisor-init
    make
    mv gvisor-init ../../dist
  )
}

install_go() {
  (
    wget "https://go.dev/dl/go1.21.2.linux-amd64.tar.gz"
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.2.linux-amd64.tar.gz
  )
  export PATH=$PATH:/usr/local/go/bin
}

build_slirpnetstack() {
  (
    git clone https://github.com/blechschmidt/slirpnetstack slirpnetstack-repo
    cd slirpnetstack-repo
    go build
  )
  mv slirpnetstack-repo/slirpnetstack .
}

build_tun2socks() {
  (
    # TODO: Use Jason Lyu's repo as soon as virtual DNS is implemented
    git clone https://github.com/blechschmidt/tun2socks tun2socks-repo
    cd tun2socks-repo
    go build
  )
  mv tun2socks-repo/tun2socks .
}

SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$SCRIPT_DIR"/..; pwd)"

# Try to introduce reproducibility
export PYTHONHASHSEED=7367789
export SOURCE_DATE_EPOCH=1


test "$MULTIARCH" = "1" && {
  TMP=$(mktemp -d)
  cp Vagrantfile "$TMP"
  cd "$TMP"
  cleanup () {
    echo "Cleaning up"
    trap "" EXIT INT TERM
    set +e
    CODE=$?
    test -z "$NOVIRT" && vagrant destroy -f
    rm -rf "$TMP"
    exit $CODE
  }
  trap cleanup INT TERM EXIT
  cp -Lrp "$PROJECT_ROOT" pallium
  set +e
  rm pallium/dist/bin/*
  set -e
  test -z "$NOVIRT" && vagrant up
  if test -z "$NOVIRT"; then
    CMD="vagrant ssh --no-tty -c"
    WDIR="/vagrant/pallium"
  else
    CMD="sh -c"
    WDIR="pallium"
  fi
  $CMD "sudo DEBIAN_FRONTEND=noninteractive apt update"
  $CMD "sudo DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade"
  $CMD "sudo DEBIAN_FRONTEND=noninteractive apt install -y qemu binfmt-support qemu-user-static docker.io"
  test -z "$NOVIRT" && vagrant halt
  test -z "$NOVIRT" && vagrant up
  $CMD "sudo docker run --rm --privileged multiarch/qemu-user-static --reset -p yes"

  set -- 'amd64' 'arm32v7' 'arm64v8' 'i386' 'ppc64le' 'riscv64' 's390x'

  for ARCH do
    IMAGE="$ARCH/ubuntu:xenial"
    test "$ARCH" = "riscv64" && IMAGE="$ARCH/ubuntu:focal"
    echo "Start build process for $ARCH"
    cp "$PROJECT_ROOT/dist/Dockerfile" "pallium/dist/Dockerfile"
    $CMD "sudo sed -i s#ubuntu:xenial#$IMAGE#g $WDIR/dist/Dockerfile"
    test -z "$NOVIRT" || WDIR=$(cd "$WDIR"; pwd)
    $CMD "sudo $WDIR/dist/build.sh --dist"
    mkdir -p "$PROJECT_ROOT/dist/bin"
    test "$ARCH" = "i386" && test -f pallium/dist/bin/pallium-x86_64 && {
      mv pallium/dist/bin/pallium-x86_64 pallium/dist/bin/pallium-i386
    }
    set +e
    mv pallium/dist/bin/* "$PROJECT_ROOT/dist/bin"
    rm pallium/dist/bin/*
    set -e
  done
  exit 0
}

require_root() {
  test "$(id -u)" -eq 0 || {
    echo "You must be root."
    exit 1
  }
}

test "$DIST" = "1" && {
  require_root
  cd ..
  docker build -f dist/Dockerfile -t pallium_build .
  docker run --rm -v "$(pwd)/"dist/bin:/pallium/dist/bin -e "BUNDLE=$BUNDLE" -t pallium_build
  exit 0
}

test "$INSTALL" = "1" && {
  require_root
  DEBIAN_FRONTEND=noninteractive apt update
  DEBIAN_FRONTEND=noninteractive apt -y install wget build-essential libreadline-dev libncursesw5-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev file pcregrep git curl
  set +e
  DEBIAN_FRONTEND=noninteractive apt -y install g++-multilib
  set -e
  wget -c https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tar.xz
  tar -Jxf Python-3.10.13.tar.xz

  # We don't use TLS/SSL anywhere, we just need to get Python to build, which is easier with OpenSSL.
  wget -c https://www.openssl.org/source/openssl-1.1.1o.tar.gz
  tar -xf openssl-1.1.1o.tar.gz
  cd openssl-1.1.1o || exit 1

  # For some reason, `uname -m` returns x86_64 the i386 image, which is probably the reason
  # why OpenSSL is compiled for 64 bits. Just cross-compile in this case.
  ARCH=$(uname -m)
  LS=$(which ls)
  if test "$ARCH" = "x86_64" && test -z "$(file "$LS" | grep -v "32-bit")"; then
    FLAGS32="-m32 linux-generic32"
    COMMAND="./Configure"
  else
    COMMAND="./config"
  fi

  # shellcheck disable=SC2086
  $COMMAND --prefix=/usr/local/custom-openssl --libdir=lib --openssldir=/etc/ssl $FLAGS32
  make depend
  make -j 32
  make install_sw
  cd ..
  cd Python-3.10.13/ || exit 1
  ./configure --enable-optimizations --with-openssl=/usr/local/custom-openssl --with-openssl-rpath=auto --enable-shared
  make -j 32 install
  cd ..
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/pallium/dist/Python-3.10.13
  update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.10 1
  python3 -m pip install pyinstaller
  python3 -m pip install ..

  test "$BUNDLE" = "1" && {
    ARCH=$(uname -m)
    test "$ARCH" != "x86_64" && {
      printf "The --bundle argument is currently only supported on x86_64\n" 1>&2
      exit 1
    }

    # Bundle Tor
    TOR_URL=$(curl -L "https://www.torproject.org/en/download/tor/" | pcregrep -o1 '"(https://archive.torproject.org/tor-package-archive/torbrowser/[^"]+)' | grep '.tar.gz$' | grep linux | grep x86_64 | head -n1)
    download_file "$TOR_URL" "tor-bundle.tar.gz"
    tar -xf tor-bundle.tar.gz
    mv tor tor-lib
    mv tor-lib/tor tor

    # Bundle gvisor's runsc
    download_gvisor

    # Bundle gvisor-init
    build_gvisor_init

    # Bundle slirpnetstack
    # Build requirement
    install_go
    build_slirpnetstack

    build_tun2socks
  }
}

if test "$BUNDLE" = "1"; then
  pyinstaller --clean -F -n pallium-"$(uname -m)"-bundle-linux --distpath bin --add-binary tun2socks:bin --add-binary tor:bin --add-binary runsc:bin --add-binary gvisor-init:bin --add-binary slirpnetstack:bin --add-data tor-lib:tor-lib --add-data ../extra/licensing:licensing bootstrap.py
else
  pyinstaller --clean -F -n pallium-"$(uname -m)"-bundle-linux --distpath bin bootstrap.py
fi
