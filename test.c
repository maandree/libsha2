/* See LICENSE file for copyright and license details. */
#include "libsha2.h"

#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define TEST_SHA256 1
#define TEST_SHA512 1


#if TEST_SHA256
# define IF_TEST_SHA256(IF, ELSE) IF
#else
# define IF_TEST_SHA256(IF, ELSE) ELSE
#endif

#if TEST_SHA512
# define IF_TEST_SHA512(IF, ELSE) IF
#else
# define IF_TEST_SHA512(IF, ELSE) ELSE
#endif


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

#define test_repeated(CHR, N, ALGO, EXPECTED)\
	do {\
		memset(buf, CHR, N);\
		test(!libsha2_init(&s, ALGO));\
		libsha2_digest(&s, buf, (N) * 8, buf);\
		libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_repeated_huge(CHR, N, ALGO, EXPECTED)\
	do {\
		size_t n__ = N;\
		if (skip_huge)\
			break;\
		memset(buf, CHR, sizeof(buf));\
		test(!libsha2_init(&s, ALGO));\
		fprintf(stderr, "processing huge message: 0 %%\n");\
		for (; n__ > sizeof(buf); n__ -= sizeof(buf)) {\
			libsha2_update(&s, buf, sizeof(buf) * 8);\
			fprintf(stderr, "\033[A\033[Kprocessing huge message: %zu %%\n", ((N) - n__) * 100 / (N));\
		}\
		libsha2_update(&s, buf, n__ * 8);\
		fprintf(stderr, "\033[A\033[K");\
		fflush(stderr);\
		libsha2_digest(&s, NULL, 0, buf);\
		libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_custom(S, ALGO, EXPECTED)\
	do {\
		test(!libsha2_init(&s, ALGO));\
		libsha2_digest(&s, S, (sizeof(S) - 1) * 8, buf);\
		libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_bits(S, N, ALGO, EXPECTED)\
	do {\
		libsha2_unhex(buf, S);\
		test(!libsha2_init(&s, ALGO));\
		libsha2_digest(&s, buf, N, buf);\
		libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));\
		test_str(str, EXPECTED);\
	} while (0)

#define test_hmac(ALGO, TEXT, KEY, MAC)\
	do {\
		libsha2_unhex(buf, KEY);\
		test(!libsha2_hmac_init(&hs, ALGO, buf, (sizeof(KEY) - 1) << 2));\
		libsha2_unhex(buf, TEXT);\
		libsha2_hmac_digest(&hs, buf, (sizeof(TEXT) - 1) << 2, buf);\
		libsha2_behex_lower(str, buf, libsha2_hmac_state_output_size(&hs));\
		test_str(str, MAC);\
	} while (0)


int
main(int argc, char *argv[])
{
	char buf[8096], str[2048];
	struct libsha2_state s;
	struct libsha2_hmac_state hs;
	int skip_huge, fds[2], status;
	size_t i, j, n, len;
	ssize_t r;
	pid_t pid;

	skip_huge = (argc == 2 && !strcmp(argv[1], "skip-huge"));

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

#if TEST_SHA256
	test(libsha2_algorithm_output_size(LIBSHA2_224) == 28);
	test(libsha2_algorithm_output_size(LIBSHA2_256) == 32);
#endif
#if TEST_SHA512
	test(libsha2_algorithm_output_size(LIBSHA2_384) == 48);
	test(libsha2_algorithm_output_size(LIBSHA2_512) == 64);
	test(libsha2_algorithm_output_size(LIBSHA2_512_224) == 28);
	test(libsha2_algorithm_output_size(LIBSHA2_512_256) == 32);
#endif
	test(!errno);
	test(libsha2_algorithm_output_size(~0) == 0); /* should test `errno == EINVAL`, optimising compiler breaks it */

	errno = 0;
	test(libsha2_init(&s, ~0) == -1 && errno == EINVAL);
	errno = 0;

#if TEST_SHA256
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
#endif

#if TEST_SHA512
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
#endif

#if TEST_SHA256
	test_repeated(0xFF, 1, LIBSHA2_224, "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5");
	test_custom("\xE5\xE0\x99\x24", LIBSHA2_224, "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d");
	test_repeated(0x00, 56, LIBSHA2_224, "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804");
	test_repeated(0x51, 1000, LIBSHA2_224, "3706197f66890a41779dc8791670522e136fafa24874685715bd0a8a");
	test_repeated(0x41, 1000, LIBSHA2_224, "a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce");
	test_repeated(0x99, 1005, LIBSHA2_224, "cb00ecd03788bf6c0908401e0eb053ac61f35e7e20a2cfd7bd96d640");
	test_repeated_huge(0x00, 1000000UL, LIBSHA2_224, "3a5d74b68f14f3a4b2be9289b8d370672d0b3d2f53bc303c59032df3");
	test_repeated_huge(0x41, 0x20000000UL, LIBSHA2_224, "c4250083cf8230bf21065b3014baaaf9f76fecefc21f91cf237dedc9");
	test_repeated_huge(0x00, 0x41000000UL, LIBSHA2_224, "014674abc5cb980199935695af22fab683748f4261d4c6492b77c543");
	test_repeated_huge(0x84, 0x6000003FUL, LIBSHA2_224, "a654b50b767a8323c5b519f467d8669837142881dc7ad368a7d5ef8f");
	test_custom("abc", LIBSHA2_224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
	test_custom("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", LIBSHA2_224,
	            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

	test_repeated(0xBD, 1, LIBSHA2_256, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b");
	test_custom("\xC9\x8C\x8E\x55", LIBSHA2_256, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504");
	test_repeated(0x00, 55, LIBSHA2_256, "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7");
	test_repeated(0x00, 56, LIBSHA2_256, "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb");
	test_repeated(0x00, 57, LIBSHA2_256, "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785");
	test_repeated(0x00, 64, LIBSHA2_256, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
	test_repeated(0x00, 1000, LIBSHA2_256, "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53");
	test_repeated(0x41, 1000, LIBSHA2_256, "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4");
	test_repeated(0x55, 1005, LIBSHA2_256, "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0");
	test_repeated_huge(0x00, 1000000UL, LIBSHA2_256, "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025");
	test_repeated_huge(0x5A, 0x20000000UL, LIBSHA2_256, "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd");
	test_repeated_huge(0x00, 0x41000000UL, LIBSHA2_256, "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53");
	test_repeated_huge(0x42, 0x6000003EUL, LIBSHA2_256, "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea");
	test_custom("abc", LIBSHA2_256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	test_custom("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", LIBSHA2_256,
	            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
#endif

#if TEST_SHA512
	test_repeated(0x00, 111, LIBSHA2_384,"435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76");
	test_repeated(0x00, 112, LIBSHA2_384, "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20");
	test_repeated(0x00, 113, LIBSHA2_384, "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21");
	test_repeated(0x00, 122, LIBSHA2_384, "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5");
	test_repeated(0x00, 1000, LIBSHA2_384, "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca");
	test_repeated(0x41, 1000, LIBSHA2_384, "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689");
	test_repeated(0x55, 1005, LIBSHA2_384, "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec");
	test_repeated_huge(0x00, 1000000UL, LIBSHA2_384, "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81");
	test_repeated_huge(0x5A, 0x20000000UL, LIBSHA2_384, "18aded227cc6b562cc7fb259e8f404549e52914531aa1c5d85167897c779cc4b25d0425fd1590e40bd763ec3f4311c1a");
	test_repeated_huge(0x00, 0x41000000UL, LIBSHA2_384, "83ab05ca483abe3faa597ad524d31291ae827c5be2b3efcb6391bfed31ccd937b6135e0378c6c7f598857a7c516f207a");
	test_repeated_huge(0x42, 0x6000003EUL, LIBSHA2_384, "cf852304f8d80209351b37ce69ca7dcf34972b4edb7817028ec55ab67ad3bc96eecb8241734258a85d2afce65d4571e2");
	test_custom("abc", LIBSHA2_384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
	test_custom("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", LIBSHA2_384,
	            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

	test_repeated(0x00, 111, LIBSHA2_512, "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c");
	test_repeated(0x00, 112, LIBSHA2_512, "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952");
	test_repeated(0x00, 113, LIBSHA2_512, "0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544");
	test_repeated(0x00, 122, LIBSHA2_512, "4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f");
	test_repeated(0x00, 1000, LIBSHA2_512, "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76");
	test_repeated(0x41, 1000, LIBSHA2_512, "329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af");
	test_repeated(0x55, 1005, LIBSHA2_512, "59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161");
	test_repeated_huge(0x00, 1000000UL, LIBSHA2_512, "ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed");
	test_repeated_huge(0x5A, 0x20000000UL, LIBSHA2_512, "da172279f3ebbda95f6b6e1e5f0ebec682c25d3d93561a1624c2fa9009d64c7e9923f3b46bcaf11d39a531f43297992ba4155c7e827bd0f1e194ae7ed6de4cac");
	test_repeated_huge(0x00, 0x41000000UL, LIBSHA2_512, "14b1be901cb43549b4d831e61e5f9df1c791c85b50e85f9d6bc64135804ad43ce8402750edbe4e5c0fc170b99cf78b9f4ecb9c7e02a157911d1bd1832d76784f");
	test_repeated_huge(0x42, 0x6000003EUL, LIBSHA2_512, "fd05e13eb771f05190bd97d62647157ea8f1f6949a52bb6daaedbad5f578ec59b1b8d6c4a7ecb2feca6892b4dc138771670a0f3bd577eea326aed40ab7dd58b1");
	test_custom("abc", LIBSHA2_512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	test_custom("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", LIBSHA2_512,
	            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

	test_repeated(0x41, 1000, LIBSHA2_512_224, "3000c31a7ab8e9c760257073c4d3be370fab6d1d28eb027c6d874f29");
	test_custom("abc", LIBSHA2_512_224, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
	test_custom("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", LIBSHA2_512_224,
	            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");

	test_repeated(0x41, 1000, LIBSHA2_512_256, "6ad592c8991fa0fc0fc78b6c2e73f3b55db74afeb1027a5aeacb787fb531e64a");
	test_custom("abc", LIBSHA2_512_256, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
	test_custom("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", LIBSHA2_512_256,
	            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
#endif

	for (i = 0; i < 1000; i++) {
		for (j = IF_TEST_SHA256(0, 2); j < IF_TEST_SHA512(6, 2); j++) {
			memset(buf, 0x41, 1000);
			test(!libsha2_init(&s, (enum libsha2_algorithm)j));
			libsha2_update(&s, buf, i * 8);
			libsha2_digest(&s, buf, (1000 - i) * 8, buf);
			libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
			test_str(str, ((const char *[]){
				"a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce",
				"c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4",
				"7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
				"329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af",
				"3000c31a7ab8e9c760257073c4d3be370fab6d1d28eb027c6d874f29",
				"6ad592c8991fa0fc0fc78b6c2e73f3b55db74afeb1027a5aeacb787fb531e64a"
			})[j]);

			memset(buf, 0x41, 1000);
			test(!libsha2_init(&s, (enum libsha2_algorithm)j));
			libsha2_update(&s, buf, i * 8);
			libsha2_update(&s, buf, (1000 - i) * 8);
			libsha2_digest(&s, NULL, 0, buf);
			libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
			test_str(str, ((const char *[]){
				"a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce",
				"c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4",
				"7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
				"329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af",
				"3000c31a7ab8e9c760257073c4d3be370fab6d1d28eb027c6d874f29",
				"6ad592c8991fa0fc0fc78b6c2e73f3b55db74afeb1027a5aeacb787fb531e64a",
			})[j]);

			if (!i)
				continue;

			memset(buf, 0x41, 1000);
			test(!libsha2_init(&s, (enum libsha2_algorithm)j));
			for (n = 0; n + i < 1000; n += i) {
				libsha2_update(&s, buf, i * 8);
				test((len = libsha2_marshal(&s, NULL)) && len <= sizeof(str));
				test(libsha2_marshal(&s, str) == len);
				memset(&s, 0, sizeof(s));
				test(libsha2_unmarshal(&s, str, sizeof(str)) == len);
			}
			libsha2_digest(&s, buf, (1000 - n) * 8, buf);
			libsha2_behex_lower(str, buf, libsha2_state_output_size(&s));
			test_str(str, ((const char *[]){
				"a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce",
				"c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4",
				"7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
				"329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af",
				"3000c31a7ab8e9c760257073c4d3be370fab6d1d28eb027c6d874f29",
				"6ad592c8991fa0fc0fc78b6c2e73f3b55db74afeb1027a5aeacb787fb531e64a",
			})[j]);
		}
	}

	test(!errno);

#if TEST_SHA256
	test(!pipe(fds));
	test((pid = fork()) >= 0);
	if (!pid) {
		close(fds[0]);
		memset(buf, 0x41, 1000);
		for (n = 1000; n; n -= (size_t)r)
			test((r = write(fds[1], buf, n < 8 ? n : 8)) > 0);
		exit(0);
	}
	close(fds[1]);
	test(!libsha2_sum_fd(fds[0], LIBSHA2_256, buf));
	test(waitpid(pid, &status, 0) == pid);
	test(!status);
	close(fds[0]);
	libsha2_behex_lower(str, buf, libsha2_algorithm_output_size(LIBSHA2_256));
	test_str(str, "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4");

	test_bits("01", 1, LIBSHA2_224, "0d05096bca2a4a77a2b47a05a59618d01174b37892376135c1b6e957");
	test_bits("02", 2, LIBSHA2_224, "ef9c947a47bb9311a0f2b8939cfc12090554868b3b64d8f71e6442f3");
	test_bits("04", 3, LIBSHA2_224, "4f2ec61c914dce56c3fe5067aa184125ab126c39edb8bf64f58bdccd");
	test_bits("05", 4, LIBSHA2_224, "b04c423c9091ff5bb32ea4b0063e98814633350c1bc2bd974f776fd2");
	test_bits("0d", 5, LIBSHA2_224, "e3b048552c3c387bcab37f6eb06bb79b96a4aee5ff27f51531a9551c");
	test_bits("2b", 6, LIBSHA2_224, "44b64a6dbd91d49df5af0c9f8e001b1378e1dc29c4b891350e5d7bd9");
	test_bits("0c", 7, LIBSHA2_224, "20f25c1fe299cf337ff7ff9cc4b5b5afac076759720174a29ba79db6");

	test(!libsha2_hmac_init(&hs, LIBSHA2_256, "", 0));
	test(libsha2_hmac_state_output_size(&hs) == 32);
	libsha2_hmac_digest(&hs, "", 0, buf);
	libsha2_behex_lower(str, buf, libsha2_hmac_state_output_size(&hs));
	test_str(str, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");

	test(!libsha2_hmac_init(&hs, LIBSHA2_256, "key", 3 << 3));
	test(libsha2_hmac_state_output_size(&hs) == 32);
	libsha2_hmac_digest(&hs, "The quick brown fox jumps over the lazy dog",
	                    (sizeof("The quick brown fox jumps over the lazy dog") - 1) << 3, buf);
	libsha2_behex_lower(str, buf, libsha2_hmac_state_output_size(&hs));
	test_str(str, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

	n = sizeof("The quick brown fox jumps over the lazy dog") - 1;
	for (i = 1; i < n; i++) {
		test(!libsha2_hmac_init(&hs, LIBSHA2_256, "key", 3 << 3));
		test(libsha2_hmac_state_output_size(&hs) == 32);
		for (j = 0; j + i < n; j += i) {
			libsha2_hmac_update(&hs, &"The quick brown fox jumps over the lazy dog"[j], i << 3);
			test((len = libsha2_hmac_marshal(&hs, NULL)) && len <= sizeof(str));
			test(libsha2_hmac_marshal(&hs, str) == len);
			memset(&hs, 0, sizeof(hs));
			test(libsha2_hmac_unmarshal(&hs, str, sizeof(str)) == len);
		}
		libsha2_hmac_digest(&hs, &"The quick brown fox jumps over the lazy dog"[j], (n - j) << 3, buf);
		libsha2_behex_lower(str, buf, libsha2_hmac_state_output_size(&hs));
		test_str(str, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
	}

	test(!errno);

	test_hmac(LIBSHA2_224,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	          "c7405e3ae058e8cd30b08b4140248581ed174cb34e1224bcc1efc81b");

	test_hmac(LIBSHA2_224,
	          "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
	          "e3d249a8cfb67ef8b7a169e9a0a599714a2cecba65999a51beb8fbbe");

	test_hmac(LIBSHA2_224,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263",
	          "91c52509e5af8531601ae6230099d90bef88aaefb961f4080abc014d");

	test_hmac(LIBSHA2_256,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	          "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62");

	test_hmac(LIBSHA2_256,
	          "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	          "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790");

	test_hmac(LIBSHA2_256,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263",
	          "bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d");
#endif

#if TEST_SHA512
	test_hmac(LIBSHA2_384,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
	          "63c5daa5e651847ca897c95814ab830bededc7d25e83eef9195cd45857a37f448947858f5af50cc2b1b730ddf29671a9");

	test_hmac(LIBSHA2_384,
	          "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
	          "6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9ff2201637b93646af5ae9ac316e98db45d9cae773675eeed0");

	test_hmac(LIBSHA2_384,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
	          "5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594");

	test_hmac(LIBSHA2_512,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
	          "fc25e240658ca785b7a811a8d3f7b4ca48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6cea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347");

	test_hmac(LIBSHA2_512,
	          "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	          "fd44c18bda0bb0a6ce0e82b031bf2818f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf710d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc");

	test_hmac(LIBSHA2_512,
	          "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
	          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
	          "d93ec8d2de1ad2a9957cb9b83f14e76ad6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce64215f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3");
#endif

	return 0;
}
