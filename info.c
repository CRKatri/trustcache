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

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "trustcache.h"

#include "compat.h"

int
tcinfo(int argc, char **argv)
{
	struct trust_cache cache;
	bool headeronly = false, onlyhash = false;
	uint32_t entrynum = 0;
	const char *errstr = NULL;

	int ch;
	while ((ch = getopt(argc, argv, "che:")) != -1) {
		switch (ch) {
			case 'h':
				headeronly = true;
				break;
			case 'e':
				entrynum = strtonum(optarg, 1, UINT32_MAX, &errstr);
				if (errstr != NULL) {
					fprintf(stderr, "entry number is %s: %s\n", errstr, optarg);
					exit(1);
				}
				break;
			case 'c':
				onlyhash = true;
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		return -1;

	cache = opentrustcache(argv[0]);

	if (entrynum == 0 && !onlyhash)
		print_header(cache);
	if (!headeronly) {
		if (onlyhash) {
			for (uint32_t i = 0; i < cache.num_entries; i++) {
				if (cache.version == 0)
					print_hash(cache.hashes[i], true);
				else if (cache.version == 1)
					print_hash(cache.entries[i].cdhash, true);
				else if (cache.version == 2)
					print_hash(cache.entries2[i].cdhash, true);
			}
			goto done;
		}
		if (entrynum != 0) {
			if (entrynum > cache.num_entries) {
				fprintf(stderr, "no entry %i\n", entrynum);
				exit(1);
			}
			if (cache.version == 0) {
				print_hash(cache.hashes[entrynum - 1], true);
			} else if (cache.version == 1) {
				print_entry(cache.entries[entrynum - 1]);
			} else if (cache.version == 2) {
				print_entry2(cache.entries2[entrynum - 1]);
			}
		} else {
			print_entries(cache);
		}
	}

done:
	free(cache.entries);

	return 0;
}

void
print_header(struct trust_cache cache)
{
	printf("version = %i\n", cache.version);
	char out[37];
	uuid_unparse(cache.uuid, out);
	printf("uuid = %s\n", out);
	printf("entry count = %i\n", cache.num_entries);
}

void
print_entries(struct trust_cache cache)
{
	for (uint32_t i = 0; i < cache.num_entries; i++) {
		if (cache.version == 0)
			print_hash(cache.hashes[i], true);
		else if (cache.version == 1)
			print_entry(cache.entries[i]);
		else if (cache.version == 2)
			print_entry2(cache.entries2[i]);
	}
}

void
print_entry(struct trust_cache_entry1 entry)
{
	print_hash(entry.cdhash, false);

	switch (entry.flags) {
		case CS_TRUST_CACHE_AMFID:
			printf(" CS_TRUST_CACHE_AMFID ");
			break;
		case CS_TRUST_CACHE_ANE:
			printf(" CS_TRUST_CACHE_ANE ");
			break;
		case CS_TRUST_CACHE_AMFID|CS_TRUST_CACHE_ANE:
			printf(" CS_TRUST_CACHE_AMFID|CS_TRUST_CACHE_ANE ");
			break;
		case 0:
			printf(" [none] ");
			break;
		default:
			printf(" [%i] ", entry.flags);
			break;
	}

	printf("[%i]\n", entry.hash_type);
}

void
print_entry2(struct trust_cache_entry2 entry)
{
	print_hash(entry.cdhash, false);

	switch (entry.flags) {
		case CS_TRUST_CACHE_AMFID:
			printf(" CS_TRUST_CACHE_AMFID ");
			break;
		case CS_TRUST_CACHE_ANE:
			printf(" CS_TRUST_CACHE_ANE ");
			break;
		case CS_TRUST_CACHE_AMFID|CS_TRUST_CACHE_ANE:
			printf(" CS_TRUST_CACHE_AMFID|CS_TRUST_CACHE_ANE ");
			break;
		case 0:
			printf(" [none] ");
			break;
		default:
			printf(" [%i] ", entry.flags);
			break;
	}

	printf("[%i] [%i]\n", entry.hash_type, entry.category);
}

void
print_hash(uint8_t cdhash[CS_CDHASH_LEN], bool newline)
{
	for (size_t j = 0; j < CS_CDHASH_LEN; j++) {
		printf("%02x", cdhash[j]);
	}
	if (newline)
		printf("\n");
}
