#ifndef _UUID_H_
#define _UUID_H_

#include <sys/types.h>

typedef unsigned char uuid_t[16];

struct uuid {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint16_t	clock_seq;
	uint8_t	node[6];
};

void uuid_generate(uuid_t out);
void uuid_unpack(const uuid_t in, struct uuid *uu);
void uuid_pack(const struct uuid *uu, uuid_t ptr);
int uuid_parse(const char *in, uuid_t uu);
void uuid_unparse(const uuid_t uu, char *out);
void uuid_copy(uuid_t dst, const uuid_t src);

#endif
