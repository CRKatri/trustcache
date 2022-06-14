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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trustcache.h"
#include "uuid/uuid.h"

int
tccreate(int argc, char **argv)
{
	struct trust_cache cache = {
		.version = 1,
		.uuid = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
		.num_entries = 0,
		.entries = NULL,
	}, append = {};

	uuid_generate(cache.uuid);

	int ch;
	while ((ch = getopt(argc, argv, "u:v:")) != -1) {
		switch (ch) {
			case 'u':
				if (uuid_parse(optarg, cache.uuid) != 0)
					fprintf(stderr, "Failed to parse %s as a UUID\n", optarg);
				break;
			case 'v':
				if (strlen(optarg) != 1 || (optarg[0] != '0' && optarg[0] != '1')) {
					fprintf(stderr, "Unsupported trustcache version %s\n", optarg);
					return 1;
				}
				if (optarg[0] == '0')
					cache.version = 0;
				else if (optarg[0] == '1')
					cache.version = 1;
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		return -1;

	for (int i = 1; i < argc; i++) {
		append = cache_from_tree(argv[i], cache.version);
		if (append.version == 0) {
			if ((cache.hashes = realloc(cache.hashes, sizeof(trust_cache_hash0) *
							(cache.num_entries + append.num_entries))) == NULL)
				exit(1);
			for (uint32_t j = 0; j < append.num_entries; j++) {
				memcpy(cache.hashes[cache.num_entries + j], append.hashes[j], CS_CDHASH_LEN);
			}
		} else if (append.version == 1) {
			if ((cache.entries = realloc(cache.entries, sizeof(struct trust_cache_entry1) *
							(cache.num_entries + append.num_entries))) == NULL)
				exit(1);
			for (uint32_t j = 0; j < append.num_entries; j++) {
				cache.entries[cache.num_entries + j].hash_type = append.entries[j].hash_type;
				cache.entries[cache.num_entries + j].flags = append.entries[j].flags;
				memcpy(cache.entries[cache.num_entries + j].cdhash, append.entries[j].cdhash, CS_CDHASH_LEN);
			}
		}
		free(append.hashes);
		cache.num_entries += append.num_entries;
	}

	if (cache.version == 1)
		qsort(cache.entries, cache.num_entries, sizeof(*cache.entries), ent_cmp);
	else if (cache.version == 0)
		qsort(cache.hashes, cache.num_entries, sizeof(*cache.hashes), hash_cmp);

	if (writetrustcache(cache, argv[0]) == -1)
		return 1;

	free(cache.entries);

	return 0;
}
