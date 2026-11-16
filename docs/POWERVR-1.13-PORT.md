# PowerVR 1.13 to Lenovo 4.9 interfaces

Owner requested an unattended port of 1.13@5776728 to the current Lenovo TB-X606V kernel on November 16, 2026, following authorization to flash and test a compatible driver.

Shipping kernel: 4.9.190+, with the 1.11@5425693 GPU driver built in. The exact shipping source is unavailable. The available Lenovo source is 4.9.117, so the first compile is an interface port against that tree, not a reproduction of the shipping kernel. This distinction must remain in build receipts.

Pinned newer driver source: rabbit-hmi-oss/android_kernel_rabbit_mt6765 at 8167c8c1087f057d2ef302fc93b47554291687ec, directory drivers/gpu/mediatek/gpu_rgx/m1.13ED5776728. Its configuration and hardware table include 22.87.104.18. Kernel API compatibility must be compiled and checked; matching GPU firmware and userspace libraries remain required.

The stage script selects only the new driver, adapts MediaTek include paths to the Lenovo layout, and uses the driver's existing older-kernel fence and ION branches. It does not disable compatibility checks or replace fence waits with success.

Flashing requires a usable matching kernel/firmware/userspace stack, board integration checks, a verified backup of the running boot image, and a recoverable bounded test. A successful compile alone is insufficient.
