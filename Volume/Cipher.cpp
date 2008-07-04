/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform/Platform.h"
#include "Cipher.h"
#include "Crypto/Aes.h"
#include "Crypto/Blowfish.h"
#include "Crypto/Des.h"
#include "Crypto/Cast.h"
#include "Crypto/Serpent.h"
#include "Crypto/Twofish.h"

namespace TrueCrypt
{
	Cipher::Cipher () : Initialized (false)
	{
	}

	Cipher::~Cipher ()
	{
	}

	void Cipher::DecryptBlock (byte *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Decrypt (data);
	}

	void Cipher::EncryptBlock (byte *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Encrypt (data);
	}

	CipherList Cipher::GetAvailableCiphers ()
	{
		CipherList l;

		l.push_back (shared_ptr <Cipher> (new CipherAES ()));
		l.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		l.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		l.push_back (shared_ptr <Cipher> (new CipherBlowfish ()));
		l.push_back (shared_ptr <Cipher> (new CipherCast5 ()));
		l.push_back (shared_ptr <Cipher> (new CipherTripleDES ()));

		return l;
	}

	void Cipher::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != GetKeySize ())
			throw ParameterIncorrect (SRC_POS);

		if (!Initialized)
			ScheduledKey.Allocate (GetScheduledKeySize ());

		SetCipherKey (key);
		Key.CopyFrom (key);
		Initialized = true;
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (CipherException);


	// AES
	void CipherAES::Decrypt (byte *data) const
	{
		aes_decrypt (data, data, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx)));
	}

	void CipherAES::Encrypt (byte *data) const
	{
		aes_encrypt (data, data, (aes_encrypt_ctx *) ScheduledKey.Ptr());
	}

	size_t CipherAES::GetScheduledKeySize () const
	{
		return sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx);
	}

	void CipherAES::SetCipherKey (const byte *key)
	{
		if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ScheduledKey.Ptr()) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);

		if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx))) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);
	}

	
	// Blowfish
	void CipherBlowfish::Decrypt (byte *data) const
	{
		BF_ecb_le_encrypt (data, data, (BF_KEY *) ScheduledKey.Ptr(), 0);
	}

	void CipherBlowfish::Encrypt (byte *data) const
	{
		BF_ecb_le_encrypt (data, data, (BF_KEY *) ScheduledKey.Ptr(), 1);
	}

	size_t CipherBlowfish::GetScheduledKeySize () const
	{
		return 4168;
	}

	void CipherBlowfish::SetCipherKey (const byte *key)
	{
		BF_set_key ((BF_KEY *) ScheduledKey.Ptr(), static_cast<int> (GetKeySize ()), (unsigned char *) key);
	}


	// CAST5
	void CipherCast5::Decrypt (byte *data) const
	{
		CAST_ecb_encrypt (data, data, (CAST_KEY *) ScheduledKey.Ptr(), 0);
	}

	void CipherCast5::Encrypt (byte *data) const
	{
		CAST_ecb_encrypt (data, data, (CAST_KEY *) ScheduledKey.Ptr(), 1);
	}

	size_t CipherCast5::GetScheduledKeySize () const
	{
		return 128;
	}

	void CipherCast5::SetCipherKey (const byte *key)
	{
		CAST_set_key((CAST_KEY *) ScheduledKey.Ptr(), static_cast<int> (GetKeySize ()), (unsigned char *) key);
	}


	// Serpent
	void CipherSerpent::Decrypt (byte *data) const
	{
		serpent_decrypt (data, data, ScheduledKey);
	}

	void CipherSerpent::Encrypt (byte *data) const
	{
		serpent_encrypt (data, data, ScheduledKey);
	}
	
	size_t CipherSerpent::GetScheduledKeySize () const
	{
		return 140*4;
	}

	void CipherSerpent::SetCipherKey (const byte *key)
	{
		serpent_set_key (key, static_cast<int> (GetKeySize ()), ScheduledKey);
	}


	// Triple-DES
	void CipherTripleDES::Decrypt (byte *data) const
	{
		des_ecb3_encrypt ((des_cblock *) data, (des_cblock *) data,
			(des_ks_struct *) ScheduledKey.Ptr(),
			(des_ks_struct *) (ScheduledKey.Ptr() + 128),
			(des_ks_struct *) (ScheduledKey.Ptr() + 128 * 2), 0);
	}

	void CipherTripleDES::Encrypt (byte *data) const
	{
		des_ecb3_encrypt ((des_cblock *) data, (des_cblock *) data,
			(des_ks_struct *) ScheduledKey.Ptr(),
			(des_ks_struct *) (ScheduledKey.Ptr() + 128),
			(des_ks_struct *) (ScheduledKey.Ptr() + 128 * 2), 1);
	}

	size_t CipherTripleDES::GetScheduledKeySize () const
	{
		return 128 * 3;
	}

	void CipherTripleDES::SetCipherKey (const byte *key)
	{
		des_key_sched ((des_cblock *) (key + 8 * 0), (struct des_ks_struct *) (ScheduledKey.Ptr() + 128 * 0));
		des_key_sched ((des_cblock *) (key + 8 * 1), (struct des_ks_struct *) (ScheduledKey.Ptr() + 128 * 1));
		des_key_sched ((des_cblock *) (key + 8 * 2), (struct des_ks_struct *) (ScheduledKey.Ptr() + 128 * 2));
	}


	// Twofish
	void CipherTwofish::Decrypt (byte *data) const
	{
		twofish_decrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	void CipherTwofish::Encrypt (byte *data) const
	{
		twofish_encrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	size_t CipherTwofish::GetScheduledKeySize () const
	{
		return TWOFISH_KS;
	}

	void CipherTwofish::SetCipherKey (const byte *key)
	{
		twofish_set_key ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *) key, static_cast<int> (GetKeySize ()) * 8);
	}
}
