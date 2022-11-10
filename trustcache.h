#ifndef _TRUSTCACHE_H_
#define _TRUSTCACHE_H_

#include <stdbool.h>
#include <sys/types.h>

#if __APPLE__
#	include <libkern/OSByteOrder.h>
#	define htole32(x) OSSwapHostToLittleInt32(x)
#	define le32toh(x) OSSwapLittleToHostInt32(x)
#elif __has_include(<endian.h>)
#	include <endian.h>
#else
#	include <sys/endian.h>
#endif

#include "machoparse/cs_blobs.h"
#include "uuid/uuid.h"

struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));

struct trust_cache_entry1 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
} __attribute__((__packed__));

typedef uint8_t trust_cache_hash0[CS_CDHASH_LEN];

struct trust_cache {
	uint32_t version;
	uuid_t uuid;
	uint32_t num_entries;
	union {
		struct trust_cache_entry2 *entries2;
		struct trust_cache_entry1 *entries;
		trust_cache_hash0 *hashes;
	};
} __attribute__((__packed__));

// flags
#define CS_TRUST_CACHE_AMFID 0x1
#define CS_TRUST_CACHE_ANE   0x2

struct trust_cache opentrustcache(const char *path);
int writetrustcache(struct trust_cache cache, const char *path);
struct trust_cache cache_from_tree(const char *path, uint32_t version);

int tcinfo(int argc, char **argv);
int tccreate(int argc, char **argv);
int tcappend(int argc, char **argv);
int tcremove(int argc, char **argv);

int ent_cmp(const void * vp1, const void * vp2);
int hash_cmp(const void * vp1, const void * vp2);

void print_header(struct trust_cache cache);
void print_hash(uint8_t cdhash[CS_CDHASH_LEN], bool newline);
void print_entry(struct trust_cache_entry1 entry);
void print_entry2(struct trust_cache_entry2 entry);
void print_entries(struct trust_cache cache);

#endif
