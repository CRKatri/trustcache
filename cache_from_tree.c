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

#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <string.h>

#include "trustcache.h"
#include "machoparse/cdhash.h"

static struct trust_cache cache = {};

static int
tccallback(const char *path, const struct stat *sb, int typeflag, struct FTW *ftw)
{
	if (!S_ISREG(sb->st_mode))
		return 0;

	struct cdhashes c = {};
	c.count = 0;
	find_cdhash(path, sb, &c);

	if (c.count == 0)
		return 0;

	for (int i = 0; i < c.count; i++) {
		if (cache.version == 0) {
			if ((cache.hashes = realloc(cache.hashes, sizeof(trust_cache_hash0) * (cache.num_entries + 1))) == NULL)
				exit(1);
			memcpy(cache.hashes[cache.num_entries], c.h[i].cdhash, CS_CDHASH_LEN);
		} else if (cache.version == 1) {
			if ((cache.entries = realloc(cache.entries, sizeof(struct trust_cache_entry1) * (cache.num_entries + 1))) == NULL)
				exit(1);
			cache.entries[cache.num_entries].hash_type = c.h[i].hash_type;
			cache.entries[cache.num_entries].flags = 0;
			memcpy(cache.entries[cache.num_entries].cdhash, c.h[i].cdhash, CS_CDHASH_LEN);
		}
		cache.num_entries++;
	}

	free(c.h);

	return 0;
}

struct trust_cache
cache_from_tree(const char *path, uint32_t version)
{
	struct trust_cache ret = {};
	cache.version = version;
	cache.num_entries = 0;
	ret.version = version;

	if (nftw(path, tccallback, 20, 0) == -1) {
		perror("nftw");
		return ret;
	}

	ret.num_entries = cache.num_entries;
	ret.hashes = cache.hashes;
	return ret;
}
