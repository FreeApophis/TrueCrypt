/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

// Total memory required (CODE + DATA + BSS + STACK + 0x100) in KBytes - determined from linker map.
#define TC__BOOT_MEMORY_REQUIRED	42

// Windows Vista boot loader uses memory up to 8000:FFFF, disregarding the BIOS memory map and the amount
// of available memory at 0:0413. Therefore, the code has to be loaded at or above 9000:0000.

// Modifying this value can introduce incompatibility with previous versions
#define TC__BOOT_LOADER_SEGMENT		TC_HEX (9000)
#define TC__BOOT_LOADER_OFFSET		TC_HEX (100) // COM executable offset

#define TC__BOOT_LOADER_LOWMEM_SEGMENT	TC_HEX (2000)
#define TC__BOOT_LOADER_BUFFER_SEGMENT	TC_HEX (5000)

#define TC__BOOT_LOADER_AREA_SECTOR_COUNT 63

#define TC__BOOT_SECTOR_CONFIG_OFFSET 439 // Last byte reserved for boot loader

#ifdef TC_ASM_PREPROCESS

#define TC_HEX(N) 0##N##h

TC_BOOT_MEMORY_REQUIRED = TC__BOOT_MEMORY_REQUIRED
TC_BOOT_LOADER_SEGMENT = TC__BOOT_LOADER_SEGMENT
TC_BOOT_LOADER_OFFSET = TC__BOOT_LOADER_OFFSET
TC_BOOT_LOADER_LOWMEM_SEGMENT = TC__BOOT_LOADER_LOWMEM_SEGMENT
TC_BOOT_LOADER_AREA_SECTOR_COUNT = TC__BOOT_LOADER_AREA_SECTOR_COUNT
TC_BOOT_SECTOR_CONFIG_OFFSET = TC__BOOT_SECTOR_CONFIG_OFFSET

#else

#define TC_HEX(N) 0x##N

#define TC_BOOT_MEMORY_REQUIRED TC__BOOT_MEMORY_REQUIRED
#define TC_BOOT_LOADER_SEGMENT TC__BOOT_LOADER_SEGMENT
#define TC_BOOT_LOADER_OFFSET TC__BOOT_LOADER_OFFSET
#define TC_BOOT_LOADER_LOWMEM_SEGMENT TC__BOOT_LOADER_LOWMEM_SEGMENT
#define TC_BOOT_LOADER_BUFFER_SEGMENT TC__BOOT_LOADER_BUFFER_SEGMENT
#define TC_BOOT_LOADER_AREA_SECTOR_COUNT TC__BOOT_LOADER_AREA_SECTOR_COUNT
#define TC_BOOT_SECTOR_CONFIG_OFFSET TC__BOOT_SECTOR_CONFIG_OFFSET

#endif
