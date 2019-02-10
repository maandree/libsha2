/* See LICENSE file for copyright and license details. */
#include "libsha2.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define test(EXPR)\
	do {\
		if (EXPR)\
			break;\
		fprintf(stderr, "Failure at line %i: %s\n", __LINE__, #EXPR);\
		exit(1);\
	} while (0)

#define test_str(HAVE, EXPECTED)\
	do {\
		if (!strcmp(HAVE, EXPECTED))\
			break;\
		fprintf(stderr, "Failure at line %i: expected \"%s\", got \"%s\"\n", __LINE__, EXPECTED, HAVE);\
		exit(1);\
	} while (0)


int
main(void)
{
	char buf[1024], str[1024];
	struct libsha2_state s;

	libsha2_behex_lower(buf, "", 0);
	test_str(buf, "");

	libsha2_behex_lower(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
	test_str(buf, "00112233445566778899aabbccddeeff");

	libsha2_behex_lower(buf, "\x1E\x5A\xC0", 3);
	test_str(buf, "1e5ac0");

	libsha2_behex_upper(buf, "", 0);
	test_str(buf, "");

	libsha2_behex_upper(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
	test_str(buf, "00112233445566778899AABBCCDDEEFF");

	libsha2_behex_upper(buf, "\x1E\x5A\xC0", 3);
	test_str(buf, "1E5AC0");

	libsha2_unhex(buf, "");
	test(!memcmp(buf, "", 0));

	libsha2_unhex(buf, "00112233445566778899AABBCCDDEEFF");
	test(!memcmp(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16));

	libsha2_unhex(buf, "1E5AC0");
	test(!memcmp(buf, "\x1E\x5A\xC0", 3));

	libsha2_unhex(buf, "00112233445566778899aabbccddeeff");
	test(!memcmp(buf, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16));

	libsha2_unhex(buf, "1e5ac0");
	test(!memcmp(buf, "\x1E\x5A\xC0", 3));

	libsha2_unhex(buf, "AAbbCcdD");
	test(!memcmp(buf, "\xAA\xBB\xCC\xDD", 4));

	test(libsha2_algorithm_output_size(LIBSHA2_224) == 28);
	test(libsha2_algorithm_output_size(LIBSHA2_256) == 32);
	test(libsha2_algorithm_output_size(LIBSHA2_384) == 48);
	test(libsha2_algorithm_output_size(LIBSHA2_512) == 64);
	test(libsha2_algorithm_output_size(LIBSHA2_512_224) == 28);
	test(libsha2_algorithm_output_size(LIBSHA2_512_256) == 32);
	test(!errno);
	test(libsha2_algorithm_output_size(~0) == 0); /* should test `errno == EINVAL`, optimising compiler breaks it */

	errno = 0;
	test(libsha2_init(&s, ~0) == -1 && errno == EINVAL);
	errno = 0;

	test(!libsha2_init(&s, LIBSHA2_224));
	test(libsha2_state_output_size(&s) == 28);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

	test(!libsha2_init(&s, LIBSHA2_256));
	test(libsha2_state_output_size(&s) == 32);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	test(!libsha2_init(&s, LIBSHA2_384));
	test(libsha2_state_output_size(&s) == 48);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

	test(!libsha2_init(&s, LIBSHA2_512));
	test(libsha2_state_output_size(&s) == 64);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

	test(!libsha2_init(&s, LIBSHA2_512_224));
	test(libsha2_state_output_size(&s) == 28);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");

	test(!libsha2_init(&s, LIBSHA2_512_256));
	test(libsha2_state_output_size(&s) == 32);
	libsha2_digest(&s, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
	test_str(str, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");

	test(!errno);

	return 0;
}
