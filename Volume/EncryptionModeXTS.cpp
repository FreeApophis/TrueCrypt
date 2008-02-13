/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "EncryptionModeXTS.h"
#include "Common/Crypto.h"

namespace TrueCrypt
{
	void EncryptionModeXTS::Encrypt (byte *data, uint64 length) const
	{
		EncryptBuffer (data, length, 0);
	}

	void EncryptionModeXTS::EncryptBuffer (byte *data, uint64 length, uint64 startDataUnitNo) const
	{
		if_debug (ValidateState ());
		
		CipherList::const_iterator iSecondaryCipher = SecondaryCiphers.begin();
		foreach_ref (const Cipher &cipher, Ciphers)
		{
			EncryptBufferXTS (cipher, **iSecondaryCipher, data, length, startDataUnitNo, 0);
			++iSecondaryCipher;
		}

		assert (iSecondaryCipher == SecondaryCiphers.end());
	}

	void EncryptionModeXTS::EncryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, byte *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
		byte finalCarry;
		byte whiteningValues [ENCRYPTION_DATA_UNIT_SIZE];
		byte whiteningValue [BYTES_PER_XTS_BLOCK];
		byte byteBufUnitNo [BYTES_PER_XTS_BLOCK];
		uint64 *whiteningValuesPtr64 = (uint64 *) whiteningValues;
		uint64 *whiteningValuePtr64 = (uint64 *) whiteningValue;
		uint64 *bufPtr = (uint64 *) buffer;
		unsigned int startBlock = startCipherBlockNo, endBlock, block;
		uint64 *const finalInt64WhiteningValuesPtr = whiteningValuesPtr64 + sizeof (whiteningValues) / sizeof (*whiteningValuesPtr64) - 1;
		uint64 blockCount, dataUnitNo;

		/* The encrypted data unit number (i.e. the resultant ciphertext block) is to be multiplied in the
		finite field GF(2^128) by j-th power of n, where j is the sequential plaintext/ciphertext block
		number and n is 2, a primitive element of GF(2^128). This can be (and is) simplified and implemented
		as a left shift of the preceding whitening value by one bit (with carry propagating). In addition, if
		the shift of the highest byte results in a carry, 135 is XORed into the lowest byte. The value 135 is
		derived from the modulus of the Galois Field (x^128+x^7+x^2+x+1). */

		// Convert the 64-bit data unit number into a little-endian 16-byte array. 
		// Note that as we are converting a 64-bit number into a 16-byte array we can always zero the last 8 bytes.
		dataUnitNo = startDataUnitNo;
		*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		*((uint64 *) byteBufUnitNo + 1) = 0;

		if (length % BYTES_PER_XTS_BLOCK)
			TC_THROW_FATAL_EXCEPTION;

		blockCount = length / BYTES_PER_XTS_BLOCK;

		// Process all blocks in the buffer
		// When length > ENCRYPTION_DATA_UNIT_SIZE, this can be parallelized (one data unit per core)
		while (blockCount > 0)
		{
			if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
				endBlock = startBlock + (unsigned int) blockCount;
			else
				endBlock = BLOCKS_PER_XTS_DATA_UNIT;

			whiteningValuesPtr64 = finalInt64WhiteningValuesPtr;
			whiteningValuePtr64 = (uint64 *) whiteningValue;

			// Encrypt the data unit number using the secondary key (in order to generate the first 
			// whitening value for this data unit)
			*whiteningValuePtr64 = *((uint64 *) byteBufUnitNo);
			*(whiteningValuePtr64 + 1) = 0;
			secondaryCipher.EncryptBlock (whiteningValue);

			// Generate subsequent whitening values for blocks in this data unit. Note that all generated 128-bit
			// whitening values are stored in memory as a sequence of 64-bit integers in reverse order.
			for (block = 0; block < endBlock; block++)
			{
				if (block >= startBlock)
				{
					*whiteningValuesPtr64-- = *whiteningValuePtr64++;
					*whiteningValuesPtr64-- = *whiteningValuePtr64;
				}
				else
					whiteningValuePtr64++;

				// Derive the next whitening value

#if BYTE_ORDER != BIG_ENDIAN

				// Little-endian platforms (Intel, AMD, etc.)

				finalCarry = 
					(*whiteningValuePtr64 & 0x8000000000000000ULL) ?
					135 : 0;

				*whiteningValuePtr64-- <<= 1;

				if (*whiteningValuePtr64 & 0x8000000000000000ULL)
					*(whiteningValuePtr64 + 1) |= 1;	

				*whiteningValuePtr64 <<= 1;

#else
				// Big-endian platforms (PowerPC, Motorola, etc.)

				finalCarry = 
					(*whiteningValuePtr64 & 0x80) ?
					135 : 0;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);

				--whiteningValuePtr64;

				if (*whiteningValuePtr64 & 0x80)
					*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;	

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
#endif

				whiteningValue[0] ^= finalCarry;
			}

			whiteningValuesPtr64 = finalInt64WhiteningValuesPtr;

			// Encrypt all blocks in this data unit
			// TO DO: This should be parallelized (one block per core)
			for (block = startBlock; block < endBlock; block++)
			{
				// Pre-whitening
				*bufPtr++ ^= *whiteningValuesPtr64--;
				*bufPtr-- ^= *whiteningValuesPtr64++;

				// Actual encryption
				cipher.EncryptBlock (reinterpret_cast <byte *> (bufPtr));

				// Post-whitening
				*bufPtr++ ^= *whiteningValuesPtr64--;
				*bufPtr++ ^= *whiteningValuesPtr64--;

				blockCount--;
			}

			startBlock = 0;

			dataUnitNo++;

			*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		}

		FAST_ERASE64 (whiteningValue, sizeof(whiteningValue));
		FAST_ERASE64 (whiteningValues, sizeof(whiteningValues));
	}

	void EncryptionModeXTS::EncryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}
	
	size_t EncryptionModeXTS::GetKeySize () const
	{
		if (Ciphers.empty())
			throw NotInitialized (SRC_POS);
		
		size_t keySize = 0;
		foreach_ref (const Cipher &cipher, SecondaryCiphers)
		{
			keySize += cipher.GetKeySize();
		}

		return keySize;
	}

	void EncryptionModeXTS::Decrypt (byte *data, uint64 length) const
	{
		DecryptBuffer (data, length, 0);
	}

	void EncryptionModeXTS::DecryptBuffer (byte *data, uint64 length, uint64 startDataUnitNo) const
	{
		if_debug (ValidateState ());
		
		CipherList::const_iterator iSecondaryCipher = SecondaryCiphers.end();
		foreach_reverse_ref (const Cipher &cipher, Ciphers)
		{
			--iSecondaryCipher;
			DecryptBufferXTS (cipher, **iSecondaryCipher, data, length, startDataUnitNo, 0);
		}

		assert (iSecondaryCipher == SecondaryCiphers.begin());
	}

	void EncryptionModeXTS::DecryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, byte *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
		byte finalCarry;
		byte whiteningValues [ENCRYPTION_DATA_UNIT_SIZE];
		byte whiteningValue [BYTES_PER_XTS_BLOCK];
		byte byteBufUnitNo [BYTES_PER_XTS_BLOCK];
		uint64 *whiteningValuesPtr64 = (uint64 *) whiteningValues;
		uint64 *whiteningValuePtr64 = (uint64 *) whiteningValue;
		uint64 *bufPtr = (uint64 *) buffer;
		unsigned int startBlock = startCipherBlockNo, endBlock, block;
		uint64 *const finalInt64WhiteningValuesPtr = whiteningValuesPtr64 + sizeof (whiteningValues) / sizeof (*whiteningValuesPtr64) - 1;
		uint64 blockCount, dataUnitNo;

		// Convert the 64-bit data unit number into a little-endian 16-byte array. 
		// Note that as we are converting a 64-bit number into a 16-byte array we can always zero the last 8 bytes.
		dataUnitNo = startDataUnitNo;
		*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		*((uint64 *) byteBufUnitNo + 1) = 0;

		if (length % BYTES_PER_XTS_BLOCK)
			TC_THROW_FATAL_EXCEPTION;

		blockCount = length / BYTES_PER_XTS_BLOCK;

		// Process all blocks in the buffer
		// When length > ENCRYPTION_DATA_UNIT_SIZE, this can be parallelized (one data unit per core)
		while (blockCount > 0)
		{
			if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
				endBlock = startBlock + (unsigned int) blockCount;
			else
				endBlock = BLOCKS_PER_XTS_DATA_UNIT;

			whiteningValuesPtr64 = finalInt64WhiteningValuesPtr;
			whiteningValuePtr64 = (uint64 *) whiteningValue;

			// Encrypt the data unit number using the secondary key (in order to generate the first 
			// whitening value for this data unit)
			*whiteningValuePtr64 = *((uint64 *) byteBufUnitNo);
			*(whiteningValuePtr64 + 1) = 0;
			secondaryCipher.EncryptBlock (whiteningValue);

			// Generate subsequent whitening values for blocks in this data unit. Note that all generated 128-bit
			// whitening values are stored in memory as a sequence of 64-bit integers in reverse order.
			for (block = 0; block < endBlock; block++)
			{
				if (block >= startBlock)
				{
					*whiteningValuesPtr64-- = *whiteningValuePtr64++;
					*whiteningValuesPtr64-- = *whiteningValuePtr64;
				}
				else
					whiteningValuePtr64++;

				// Derive the next whitening value

#if BYTE_ORDER != BIG_ENDIAN

				finalCarry = 
					(*whiteningValuePtr64 & 0x8000000000000000ULL) ?
					135 : 0;

				*whiteningValuePtr64-- <<= 1;

				if (*whiteningValuePtr64 & 0x8000000000000000ULL)
					*(whiteningValuePtr64 + 1) |= 1;	

				*whiteningValuePtr64 <<= 1;

#else

				finalCarry = 
					(*whiteningValuePtr64 & 0x80) ?
					135 : 0;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
				--whiteningValuePtr64;

				if (*whiteningValuePtr64 & 0x80)
					*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;	

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
#endif

				whiteningValue[0] ^= finalCarry;
			}

			whiteningValuesPtr64 = finalInt64WhiteningValuesPtr;

			// Decrypt blocks in this data unit
			// TO DO: This should be parallelized (one block per core)
			for (block = startBlock; block < endBlock; block++)
			{
				*bufPtr++ ^= *whiteningValuesPtr64--;
				*bufPtr-- ^= *whiteningValuesPtr64++;

				cipher.DecryptBlock (reinterpret_cast <byte *> (bufPtr));

				*bufPtr++ ^= *whiteningValuesPtr64--;
				*bufPtr++ ^= *whiteningValuesPtr64--;

				blockCount--;
			}

			startBlock = 0;

			dataUnitNo++;

			*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		}

		FAST_ERASE64 (whiteningValue, sizeof(whiteningValue));
		FAST_ERASE64 (whiteningValues, sizeof(whiteningValues));
	}
	
	void EncryptionModeXTS::DecryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		DecryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}

	void EncryptionModeXTS::SetCiphers (const CipherList &ciphers)
	{
		EncryptionMode::SetCiphers (ciphers);

		SecondaryCiphers.clear();

		foreach_ref (const Cipher &cipher, ciphers)
		{
			SecondaryCiphers.push_back (cipher.GetNew());
		}

		if (SecondaryKey.Size() > 0)
			SetSecondaryCipherKeys();
	}

	void EncryptionModeXTS::SetKey (const ConstBufferPtr &key)
	{
		SecondaryKey.Allocate (key.Size());
		SecondaryKey.CopyFrom (key);

		if (!SecondaryCiphers.empty())
			SetSecondaryCipherKeys();
	}
	
	void EncryptionModeXTS::SetSecondaryCipherKeys ()
	{
		size_t keyOffset = 0;
		foreach_ref (Cipher &cipher, SecondaryCiphers)
		{
			cipher.SetKey (SecondaryKey.GetRange (keyOffset, cipher.GetKeySize()));
			keyOffset += cipher.GetKeySize();
		}

		KeySet = true;
	}
}
