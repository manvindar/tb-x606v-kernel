#!/bin/bash
# Runs in the arm64 Linux VM. usage: build-mainline.sh /path/to/tb-x606v-kernel
set -e
REPO=$1; W=$HOME/k510; V=5.10.272; mkdir -p $W; cd $W
sudo apt-get install -y -qq make gcc bc bison flex libssl-dev device-tree-compiler busybox-static cpio xz-utils libelf-dev >/dev/null
[ -d linux-$V ] || { curl -sfL https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$V.tar.xz | tar xJ; }
cd linux-$V
cp $REPO/mainline/tb-x606v.dts arch/arm64/boot/dts/mediatek/
grep -q tb-x606v arch/arm64/boot/dts/mediatek/Makefile || echo 'dtb-$(CONFIG_ARCH_MEDIATEK) += tb-x606v.dtb' >> arch/arm64/boot/dts/mediatek/Makefile
make defconfig >/dev/null
scripts/config -e ARCH_MEDIATEK -e SERIAL_8250 -e SERIAL_8250_CONSOLE -e SERIAL_8250_MT6577 -e PSTORE -e PSTORE_CONSOLE -e PSTORE_RAM \
  -e DEVTMPFS -e DEVTMPFS_MOUNT -e BLK_DEV_INITRD -e RD_GZIP -d MODULES -d EFI -d KVM -d DRM -d WLAN -d WIRELESS -d BT -d SOUND -d USB_SUPPORT -d NFS_FS
make olddefconfig >/dev/null
# initramfs: static busybox, prints a banner, then idles (keeps the kernel alive; log is in pstore)
rm -rf $W/rootfs; mkdir -p $W/rootfs/{bin,proc,sys,dev}; cp /bin/busybox $W/rootfs/bin/; for a in sh sleep cat mount echo dmesg uname; do ln -sf busybox $W/rootfs/bin/$a; done
cat > $W/rootfs/init <<'INIT'
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys
echo "TB-X606V mainline: $(uname -r) reached userspace" > /dev/kmsg
dmesg > /dev/kmsg 2>/dev/null
while :; do echo "tb-x606v alive $(cat /proc/uptime)" > /dev/kmsg; sleep 5; done
INIT
chmod +x $W/rootfs/init
(cd $W/rootfs && find . | cpio -o -H newc 2>/dev/null | gzip -9 > $W/initramfs.cpio.gz)
scripts/config --set-str INITRAMFS_SOURCE $W/rootfs
make -j8 Image.gz dtbs > $W/build.log 2>&1 || { grep -E "error|Error" $W/build.log | head; exit 1; }
cat arch/arm64/boot/Image.gz arch/arm64/boot/dts/mediatek/tb-x606v.dtb > $W/Image.gz-dtb
cp arch/arm64/boot/dts/mediatek/tb-x606v.dtb $W/
ls -l $W/Image.gz-dtb $W/tb-x606v.dtb
