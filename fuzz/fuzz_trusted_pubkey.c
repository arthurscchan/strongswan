/*
 * Copyright (C) 2026 Arthur SC Chan
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <library.h>
#include <utils/debug.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_trusted_pubkey");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	certificate_t *cert;
	public_key_t *key;
	chunk_t chunk, enc;

	chunk = chunk_create((u_char*)buf, len);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_TRUSTED_PUBKEY,
							  BUILD_BLOB, chunk, BUILD_END);
	if (cert)
	{
		cert->get_type(cert);
		cert->get_subject(cert);
		key = cert->get_public_key(cert);
		if (key)
		{
			key->get_type(key);
			key->get_keysize(key);
			key->destroy(key);
		}
		if (cert->get_encoding(cert, CERT_ASN1_DER, &enc))
		{
			chunk_free(&enc);
		}
		cert->destroy(cert);
	}
	return 0;
}
