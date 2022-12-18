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
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "trustcache.h"

#define STRINIZE(x) #x
#define STRINGFY(x) STRINIZE(x)

int
main(int argc, char **argv)
{
	if (argc < 2) {
help:
		fprintf(stderr, "Usage: trustcache append [-f flags] [-u uuid | 0] infile file ...\n"
										"       trustcache create [-u uuid] [-v version] outfile file ...\n"
										"       trustcache info [-c] [-h] [-e entrynum] file\n"
										"       trustcache remove [-k] file hash ...\n\n"
										"See trustcache(1) for more information\n");
		exit(1);
	}

	int ret = 1;

	if (strcmp(argv[1], "info") == 0)
		ret = tcinfo(argc - 1, argv + 1);
	else if (strcmp(argv[1], "create") == 0)
		ret = tccreate(argc - 1, argv + 1);
	else if (strcmp(argv[1], "append") == 0)
		ret = tcappend(argc - 1, argv + 1);
	else if (strcmp(argv[1], "remove") == 0)
		ret = tcremove(argc - 1, argv + 1);
#ifdef VERSION
    else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)
        fprintf(stderr, " %s, v%s\n"
                        " Supported trustcache versions: 0, 1, 2\n"
                        " See %s(1) for more information.\n",
                        argv[0], STRINGFY(VERSION), argv[0]);
#endif
	else
		fprintf(stderr, "Unknown subcommand %s\n", argv[1]);

	if (ret == -1)
		goto help;

	return ret;
}

struct trust_cache
opentrustcache(const char *path)
{
	FILE *f;
	struct trust_cache cache;

	if ((f = fopen(path, "r")) == NULL) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		exit(1);
	}

	fread(&cache, sizeof(struct trust_cache) - sizeof(struct trust_cache_entry1*), 1, f);
	cache.version = le32toh(cache.version);
	cache.num_entries = le32toh(cache.num_entries);

	if (cache.version == 0) {
		if ((cache.hashes = calloc(cache.num_entries, sizeof(trust_cache_hash0))) == NULL)
			exit(EX_OSERR);
		fread(cache.hashes, sizeof(trust_cache_hash0), cache.num_entries, f);
	} else if (cache.version == 1) {
		if ((cache.entries = calloc(cache.num_entries, sizeof(struct trust_cache_entry1))) == NULL)
			exit(EX_OSERR);
		fread(cache.entries, sizeof(struct trust_cache_entry1), cache.num_entries, f);
	} else if (cache.version == 2) {
		if ((cache.entries = calloc(cache.num_entries, sizeof(struct trust_cache_entry2))) == NULL)
			exit(EX_OSERR);
		fread(cache.entries, sizeof(struct trust_cache_entry2), cache.num_entries, f);
	} else {
		fprintf(stderr, "%s: Unsupported version %i\n", path, cache.version);
		exit(1);
	}

	fclose(f);
	return cache;
}

int
writetrustcache(struct trust_cache cache, const char *path)
{
	FILE *f = NULL;
	if ((f = fopen(path, "wb")) == NULL) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -1;
	}

	cache.version = htole32(cache.version);
	cache.num_entries = htole32(cache.num_entries);
	fwrite(&cache, sizeof(struct trust_cache) - sizeof(struct trust_cache_entry1*), 1, f);
	cache.version = le32toh(cache.version);
	cache.num_entries = le32toh(cache.num_entries);

	for (uint32_t i = 0; i < cache.num_entries; i++) {
		if (cache.version == 0)
			fwrite(&cache.hashes[i], sizeof(trust_cache_hash0), 1, f);
		else if (cache.version == 1)
			fwrite(&cache.entries[i], sizeof(struct trust_cache_entry1), 1, f);
		else if (cache.version == 2)
			fwrite(&cache.entries2[i], sizeof(struct trust_cache_entry2), 1, f);
	}

	fclose(f);
	return 0;
}
