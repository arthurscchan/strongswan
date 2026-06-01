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
#include <crypto/proposal/proposal.h>
#include <utils/debug.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	proposal_t *proposal;
	char str[1024 + 1];

	if (!len || len > sizeof(str) - 1)
	{
		return 0;
	}

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_proposal");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	memcpy(str, buf, len);
	str[len] = '\0';

	proposal = proposal_create_from_string(PROTO_IKE, str);
	DESTROY_IF(proposal);

	proposal = proposal_create_from_string(PROTO_ESP, str);
	DESTROY_IF(proposal);

	proposal = proposal_create_from_string(PROTO_AH, str);
	DESTROY_IF(proposal);

	lib->plugins->unload(lib->plugins);
	library_deinit();
	return 0;
}
