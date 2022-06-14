/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Cameron Katri.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY CAMERON KATRI AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CAMERON KATRI OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trustcache.h"
#include "uuid/uuid.h"

int
tcremove(int argc, char **argv)
{
	bool keepuuid = false;
	int numremoved = 0;

	int ch;
	while ((ch = getopt(argc, argv, "k")) != -1) {
		switch (ch) {
			case 'k':
				keepuuid = true;
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		return -1;

	FILE *f = NULL;
	struct trust_cache cache = opentrustcache(argv[0]);

	if (!keepuuid)
		uuid_generate(cache.uuid);

	uint8_t hash[CS_CDHASH_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	for (int i = 1; i < argc; i++) {
		if (strlen(argv[i]) != 40) {
			fprintf(stderr, "%s is not a valid CDHash\n", argv[i]);
			exit(1);
		}
		for (size_t j = 0; j < CS_CDHASH_LEN; j++)
			sscanf(argv[i] + 2 * j, "%02hhx", &hash[j]);

		uint32_t j = 0;
		while (j < cache.num_entries) {
			if (cache.version == 0) {
				if (memcmp(cache.hashes[j], hash, CS_CDHASH_LEN) == 0) {
					memmove(&cache.hashes[j], &cache.hashes[j + 1], (cache.num_entries - j - 1) * sizeof(trust_cache_hash0));
					cache.num_entries--;
					numremoved++;
					continue;
				}
			} else if (cache.version == 1) {
				if (memcmp(cache.entries[j].cdhash, hash, CS_CDHASH_LEN) == 0) {
					memmove(&cache.entries[j], &cache.entries[j + 1], (cache.num_entries - j - 1) * sizeof(struct trust_cache_entry1));
					cache.num_entries--;
					numremoved++;
					continue;
				}
			}
			j++;
		}
		for (size_t j = 0; j < CS_CDHASH_LEN; j++)
			hash[j] = 0;
	}

	if (writetrustcache(cache, argv[0]) == -1)
		return 1;

	free(cache.entries);

	printf("Removed %i %s\n", numremoved, numremoved == 1 ? "entry" : "entries");

	return 0;
}
