# PowerVR 1.13 to Lenovo 4.9 interfaces

Owner requested an unattended port of 1.13@5776728 to the current Lenovo TB-X606V kernel on November 16, 2026, following authorization to flash and test a compatible driver.

Shipping kernel: 4.9.190+, with the 1.11@5425693 GPU driver built in. The exact shipping source is unavailable. The available Lenovo source is 4.9.117, so the first compile is an interface port against that tree, not a reproduction of the shipping kernel. This distinction must remain in build receipts.

Pinned newer driver source: rabbit-hmi-oss/android_kernel_rabbit_mt6765 at 8167c8c1087f057d2ef302fc93b47554291687ec, directory drivers/gpu/mediatek/gpu_rgx/m1.13ED5776728. Its configuration and hardware table include 22.87.104.18. Kernel API compatibility must be compiled and checked; matching GPU firmware and userspace libraries remain required.

The stage script selects only the new driver, adapts MediaTek include paths to the Lenovo layout, and uses the driver's existing older-kernel fence and ION branches. It does not disable compatibility checks or replace fence waits with success.

Flashing requires a usable matching kernel/firmware/userspace stack, board integration checks, a verified backup of the running boot image, and a recoverable bounded test. A successful compile alone is insufficient.

## Additional source and firmware checks

The philmb3487/android_kernel_lenovo_achilles6 fork reports 4.9.190 and contains 1.11@5425693. Its history replaces the Lenovo 4.9.117 drop with an "a107 base" at 51ba160931e89c2539f5d07b4fd978dac5f63092, omits the cellular defconfig, and later modifies display interfaces. Its README reports an abandoned, unsuccessful device project. This is a source lead, not a verified shipping-kernel replacement. The MatiDEV-PL, kosmonavtika and minhng99 forks still report 4.9.117.

The Rabbit rgx.fw footer follows the pinned driver's RGX_FW_INFO_HEADER format: version 1, 32-byte header, six 24-byte layout entries, BVNC 22.87.104.18, 4096-byte pages, compatibility flags zero. scripts/inspect_rgx_firmware.py checks these fields and section bounds. This establishes footer/target compatibility, not the firmware's internal DDK build or runtime behavior. Runtime DDK checks must remain enabled.

The connected tablet uses vendor interface version 29 and seven loaded external modules, including Wi-Fi, connectivity and fpsgo. A complete replacement kernel must preserve their interfaces and symbol CRCs. Donor userspace targets vendor interface version 31; its libPVRMtkutils dependency on libgralloc_metadata remains unresolved on Lenovo. No driver or boot image has been written for this port.
