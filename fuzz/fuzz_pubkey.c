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

static builder_part_t blob_types[] = {
	BUILD_BLOB,
	BUILD_BLOB_DNSKEY,
	BUILD_BLOB_SSHKEY,
	BUILD_BLOB_PGP,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_pubkey");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	public_key_t *key;
	chunk_t chunk, fp, enc;
	int i;

	chunk = chunk_create((u_char*)buf, len);

	for (i = 0; i < countof(blob_types); i++)
	{
		key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
								 blob_types[i], chunk, BUILD_END);
		if (key)
		{
			key->get_type(key);
			key->get_keysize(key);
			key->get_fingerprint(key, KEYID_PUBKEY_INFO_SHA1, &fp);
			if (key->get_encoding(key, PUBKEY_ASN1_DER, &enc))
			{
				chunk_free(&enc);
			}
			key->destroy(key);
		}
	}
	return 0;
}
