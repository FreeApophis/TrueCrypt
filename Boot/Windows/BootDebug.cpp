/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform.h"
#include "Bios.h"
#include "BootConsoleIo.h"
#include "BootDiskIo.h"
#include "BootDebug.h"


void InitDebugPort ()
{
	__asm
	{
		mov dx, TC_DEBUG_PORT
		mov ah, 1
		int 0x17
		mov dx, TC_DEBUG_PORT
		mov ah, 0xe2
		int 0x17
	}
}


void WriteDebugPort (byte dataByte)
{
	__asm
	{
		mov al, dataByte
		mov dx, TC_DEBUG_PORT
		mov ah, 0
		int 0x17
	}
}


extern "C" void PrintDebug (uint32 debugVal)
{
	Print (debugVal);
	PrintEndl();
}


void PrintAddress (void *addr)
{
	uint16 segment = uint16 (uint32 (addr) >> 16);
	uint16 offset = uint16 (addr);

	PrintHex (segment);
	PrintChar (':');
	PrintHex (offset);
	Print (" (");
	PrintHex (GetLinearAddress (segment, offset));
	Print (")");
}


void PrintVal (const char *message, const uint32 value, bool newLine, bool hex)
{
	Print (message);
	Print (": ");
	
	if (hex)
		PrintHex (value);
	else
		Print (value);
	
	if (newLine)
		PrintEndl();
}


void PrintVal (const char *message, const uint64 &value, bool newLine, bool hex)
{
	Print (message);
	Print (": ");
	PrintHex (value);
	if (newLine)
		PrintEndl();
}


void PrintHexDump (byte *mem, size_t size, uint16 *memSegment)
{
	const size_t width = 16;
	for (size_t pos = 0; pos < size; )
	{
		for (int pass = 1; pass <= 2; ++pass)
		{
			size_t i;
			for (i = 0; i < width && pos < size; ++i)
			{
				byte dataByte;
				if (memSegment)
				{
					__asm
					{
						push es
						mov si, ss:memSegment
						mov es, ss:[si]
						mov si, ss:mem
						add si, pos
						mov al, es:[si]
						mov dataByte, al
						pop es
					}
					pos++;
				}
				else
					dataByte = mem[pos++];

				if (pass == 1)
				{
					PrintHex (dataByte);
					PrintChar (' ');
				}
				else
					PrintChar (IsPrintable (dataByte) ? dataByte : '.');
			}

			if (pass == 1)
			{
				pos -= i;
				PrintChar (' ');
			}
		}

		PrintEndl ();
	}
}


void PrintHexDump (uint16 memSegment, uint16 memOffset, size_t size)
{
	PrintHexDump ((byte *) memOffset, size, &memSegment);
}
