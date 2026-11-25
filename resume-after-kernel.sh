#!/bin/bash
# Reprend build-ipsw.sh a partir de l etape audio, sans tout refaire.
# A lancer seulement si build-ipsw.sh s est arrete a l etape audioport
# (rootfs16, rootfs16ipad, cryptexOS, cryptexApp encore montes; work/ tmp1/ tmp3/ presents).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
sudo -v || exit 1
set -euo pipefail
for d in rootfs16 rootfs16ipad cryptexOS cryptexApp; do mount | grep -q "$SCRIPT_DIR/$d " || { echo "$d n est pas monte : relance build-ipsw.sh en entier." >&2; exit 1; }; done
[[ -f work/kernel.patch2 && -f work/kernel-SE.raw && -d tmp1 && -d tmp3 ]] || { echo "work/ ou tmp1/tmp3 manquant : relance build-ipsw.sh en entier." >&2; exit 1; }
rm -f work/kernel.patch2a
python3 patchsrc/audioport/audioport.py work/kernel.patch2 work/kernel-SE.raw work/kernel.patch2a
./bin/mthax work/kernel.patch2a work/kernel.patch3
./bin/Kernel64Patcher work/kernel.patch3 work/kernel.patch4 -e -h
./bin/KPlooshFinder work/kernel.patch4 work/kernel.patch5
./bin/kerneldiff2 work/kernel.raw work/kernel.patch4 work/kernel.diff
./bin/kerneldiff2 work/kernel.raw work/kernel.patch5 work/kernel.diff2
./bin/img4 -i tmp3/kernelcache.release.ipad6f -o tmp1/kernelcache.release.iphone8b -T krnl -P work/kernel.diff
./bin/img4 -i tmp3/kernelcache.release.ipad6f -o tmp1/kernelcache.release.iphone8c -T krnl -P work/kernel.diff2
# Done with that. Can now prep Cryptex
sudo rm -rf rootfs16/System/Cryptexes/OS
sudo rm -rf rootfs16/System/Cryptexes/App
sudo mkdir -p rootfs16/System/Cryptexes/OS
sudo mkdir -p rootfs16/System/Cryptexes/App
sudo rsync -av cryptexOS/ rootfs16/System/Cryptexes/OS
sudo rsync -av cryptexApp/ rootfs16/System/Cryptexes/App
sudo mv -v rootfs16/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld rootfs16/System/Library/Caches
hdiutil detach cryptexOS
hdiutil detach cryptexApp
# Now, copy the H6ISP and fix Graphics.
sudo cp -av rootfs16ipad/System/Library/PrivateFrameworks/H6ISPServices.framework rootfs16/System/Library/PrivateFrameworks
sudo cp -av rootfs16ipad/System/Library/Extensions/AGXMetalA9.bundle rootfs16/System/Library/Extensions
hdiutil detach rootfs16ipad
rm -rf tmp2
rm -rf tmp3/078-65701-105.dmg
rm -rf tmp3/078-64804-105.dmg
rm -rf tmp3/078-64825-107.dmg
# Patch DSC. Needed for multiple functionality fixes
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.05 work/dyld05
sudo mv -v work/dyld05 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.05
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.09 work/dyld09
sudo mv -v work/dyld09 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.09
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.11 work/dyld11
sudo mv -v work/dyld11 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.11
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.13 work/dyld13
sudo mv -v work/dyld13 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.13
sudo chown root:wheel rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*
sudo chmod 755 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*
# All done with the iPad stuff.
hdiutil detach rootfs16
hdiutil convert -format ULFO -o tmp1/098-68807-067.dmg work/template.dmg
rm -rf work/template.dmg
asr imagescan --source tmp1/098-68807-067.dmg
# Patch restore ramdisk and prep restores, copy iPad 5 SEPfw
cp -v tmp3/Firmware/all_flash/sep-firmware.j72t.RELEASE.im4p tmp1/Firmware/all_flash/sep-firmware.n69.RELEASE.im4p
cp -v tmp3/Firmware/all_flash/sep-firmware.j72s.RELEASE.im4p tmp1/Firmware/all_flash/sep-firmware.n69u.RELEASE.im4p
./bin/img4 -i tmp3/078-64668-109.dmg -o work/ramdisk.raw
rm -rf tmp3
# bbupdate fix
./bin/apfs-tool work/ramdisk.raw extract usr/lib/libTelephonyUtilDynamic.dylib work/libTelephonyUtilDynamic.dylib
./bin/bbupdaterpatch work/libTelephonyUtilDynamic.dylib work/libTelephonyUtilDynamic.patch
./bin/ldid -S work/libTelephonyUtilDynamic.patch
./bin/apfs-tool work/ramdisk.raw rm usr/lib/libTelephonyUtilDynamic.dylib 
./bin/apfs-tool work/ramdisk.raw add work/libTelephonyUtilDynamic.patch usr/lib/libTelephonyUtilDynamic.dylib 
./bin/apfs-tool work/ramdisk.raw chmod 755 usr/lib/libTelephonyUtilDynamic.dylib 
# restored_external
./bin/apfs-tool work/ramdisk.raw extract usr/local/bin/restored_external work/restored_external
./bin/restored_external64_patcher work/restored_external work/restored_patch
./bin/ldid -e work/restored_external > work/ents.plist
./bin/ldid -Swork/ents.plist work/restored_patch
./bin/apfs-tool work/ramdisk.raw rm usr/local/bin/restored_external
./bin/apfs-tool work/ramdisk.raw add work/restored_patch usr/local/bin/restored_external
./bin/apfs-tool work/ramdisk.raw chmod 755 usr/local/bin/restored_external
./bin/img4 -i work/ramdisk.raw -o tmp1/098-68700-067.dmg -A -T rdsk
# Finish up!
./bin/img4 -i tmp1/Firmware/all_flash/iBoot.n69.RELEASE.im4p -o work/iBoot.dec -k ad86b28172e561c8694035de80e93ba2d4fa9cc3dcb390afeaa991dcb4310103ddfe49b69d5edad2d3989585d73c74b2
./bin/img4 -i tmp1/Firmware/all_flash/iBoot.n69u.RELEASE.im4p -o work/iBoot-n69u.dec -k b35d235c6677fb5553c1eca51207a8be6b3930cddbf2296a488cae37e5f00bfefaed17eb241114d5fed913267ea12a29
./bin/iBootpatch2 -R -i work/iBoot.dec -o work/iBoot.patch
./bin/iBootpatch2 -R -i work/iBoot-n69u.dec -o work/iBoot-n69u.patch
./bin/img4 -i work/iBoot.patch -o tmp1/Firmware/all_flash/iBoot.n69.RELEASE.im4p -A -T ibot
./bin/img4 -i work/iBoot-n69u.patch -o tmp1/Firmware/all_flash/iBoot.n69u.RELEASE.im4p -A -T ibot
rm -rf work
sudo plutil -replace ProductBuildVersion -string 20B82 tmp1/BuildManifest.plist
sudo plutil -replace ProductVersion -string 16.1 tmp1/BuildManifest.plist
sudo plutil -replace BuildIdentities.0.Manifest.KernelCache.Info.Path -string kernelcache.release.iphone8c tmp1/BuildManifest.plist
sudo plutil -replace BuildIdentities.1.Manifest.KernelCache.Info.Path -string kernelcache.release.iphone8c tmp1/BuildManifest.plist
cd tmp1 
zip -0 -r ../iPhone_4.0_64bit_16.1_20B82_Restore.ipsw *
cd ..
rm -rf "tmp1"
echo "Restore bundle is created. You can restore it via turdus merula (https://sep.lol)"
exit 0
