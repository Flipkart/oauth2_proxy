#!/bin/bash -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE=oauth2-proxy
VERSION=$(cat $DIR/version.go | grep "const VERSION" | awk '{print $NF}' | sed 's/"//g')
DEST="deb-$PACKAGE-$VERSION"
DEB="$PACKAGE-$VERSION.deb"
OS=${1:-$(go env GOOS)}
ARCH=${2:-$(go env GOARCH)}
host=${host:-"repo-svc-app-0001.nm.flipkart.com"}
port=${port:-"8080"}
repo=${repo:-"oauth2-proxy"}

echo "=============== Build Config ================="
echo "PACKAGE: $PACKAGE"
echo "VERSION: $VERSION"
echo "DEST: $DEST"
echo "DEB: $DEB"
echo "OS: $OS"
echo "ARCH: $ARCH"

echo "=============== Running tests ================="
#$DIR/test.sh
echo "not running tests"

echo "=============== Building ================="
BUILD=$(mktemp -d ${TMPDIR:-/tmp}/oauth2_proxy.XXXXXX)
GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o $BUILD/oauth2-proxy

echo "=============== Copying Package Files ==================="
rm -rf $DEST
mkdir $DEST && cp -a dist/$PACKAGE/* $DEST
cp $BUILD/oauth2-proxy $DEST/usr/share/$PACKAGE/

echo "=============== Creating DEB ====================="
sed -i -e "s/_PACKAGE_/$PACKAGE/g" $DEST/DEBIAN/control
sed -i -e "s/_VERSION_/$VERSION/g" $DEST/DEBIAN/control
sed -i -e "s/_ARCH_/$ARCH/g" $DEST/DEBIAN/control
fakeroot dpkg -b $DEST $DEB

echo "=================== Uploading to repo-svc repo $repo ========================"
reposervice --host $host --port $port pubrepo --repo $repo --appkey secret --debs $DEB
echo "Done!"

echo "=============== Cleaning Up ======================"
rm -rf /tmp/$PACKAGE-latest.deb
cp $DEB /tmp/$PACKAGE-latest.deb
rm -rf $BUILD
rm -rf $DEST $DEB