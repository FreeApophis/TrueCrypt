/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform.h"


uint64 operator+ (const uint64 &a, const uint64 &b)
{
	int carry = 0;
	uint64 r;

	r.LowPart = a.LowPart + b.LowPart;
	__asm
	{
		jnc nocarry
		mov carry, 1
	nocarry:
	}

	r.HighPart = a.HighPart + b.HighPart + carry;

	return r;
}

uint64 operator+ (const uint64 &a, uint32 b)
{
	uint64 b64;
	b64.HighPart = 0;
	b64.LowPart = b;
	return a + b64;
}

uint64 operator- (const uint64 &a, const uint64 &b)
{
	int carry = 0;
	uint64 r;

	r.LowPart = a.LowPart - b.LowPart;
	__asm
	{
		jnc nocarry
		mov carry, 1
	nocarry:
	}

	r.HighPart = a.HighPart - b.HighPart - carry;

	return r;
}

uint64 operator- (const uint64 &a, uint32 b)
{
	uint64 b64;
	b64.HighPart = 0;
	b64.LowPart = b;
	return a - b64;
}

uint64 operator>> (const uint64 &a, int shiftCount)
{
	uint64 r = a;

	while (shiftCount--)
	{
		r.LowPart >>= 1;
		
		if ((byte) r.HighPart & 1)
			r.LowPart |= 0x80000000UL;

		r.HighPart >>= 1;
	}

	return r;
}

uint64 operator<< (const uint64 &a, int shiftCount)
{
	uint64 r = a;
	
	while (shiftCount--)
		r = r + r;

	return r;
}

uint64 &operator++ (uint64 &a)
{
	return a = a + 1;
}

bool operator== (const uint64 &a, const uint64 &b)
{
	return a.HighPart == b.HighPart && a.LowPart == b.LowPart;
}

bool operator> (const uint64 &a, const uint64 &b)
{
	return (a.HighPart > b.HighPart) || (a.HighPart == b.HighPart && a.LowPart > b.LowPart);
}

bool operator< (const uint64 &a, const uint64 &b)
{
	return (a.HighPart < b.HighPart) || (a.HighPart == b.HighPart && a.LowPart < b.LowPart);
}

bool operator>= (const uint64 &a, const uint64 &b)
{
	return a > b || a == b;
}

bool operator<= (const uint64 &a, const uint64 &b)
{
	return a < b || a == b;
}

bool TestInt64 ()
{
	uint64 a, b, c;
	a.HighPart = 0x00112233UL;
	a.LowPart = 0xabcd1234UL;

	b.HighPart = 0x00ffeeddUL;
	b.LowPart = 0xffffFFFFUL;

	++a;
	b = b + (uint32) 1UL;

	c = (a - ((a + b) >> 32) - (uint32) 1UL);
	if (c.HighPart != 0x112233UL || c.LowPart != 0xAABC0123UL)
		return false;

	c = c << 9;
	return c.HighPart == 0x22446755UL && c.LowPart == 0x78024600UL;
}


void Jump (uint16 jumpSegment, uint16 jumpOffset, byte dlRegister)
{
	uint32 addr = (uint32 (jumpSegment) << 16) | jumpOffset;
	__asm
	{
		mov dl, dlRegister
		mov ax, jumpSegment
		mov ds, ax
		mov es, ax
		mov ss, ax
		mov sp, 0xffff
		jmp cs:addr
	}
}


void CopyMemory (byte *source, uint16 destSegment, uint16 destOffset, uint16 blockSize)
{
	__asm
	{
		push es
		mov si, ss:source
		mov es, ss:destSegment
		mov di, ss:destOffset
		mov cx, ss:blockSize
		cld
		rep movsb
		pop es
	}
}


void CopyMemory (uint16 sourceSegment, uint16 sourceOffset, byte *destination, uint16 blockSize)
{
	__asm
	{
		push ds
		push es
		mov ax, ds
		mov es, ax
		mov di, ss:destination
		mov si, ss:sourceOffset
		mov cx, ss:blockSize
		mov ds, ss:sourceSegment
		cld
		rep movsb
		pop es
		pop ds
	}
}


uint32 GetLinearAddress (uint16 segment, uint16 offset)
{
	return (uint32 (segment) << 4) + offset;
}
