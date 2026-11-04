CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude -Ihxcrypt/include -DKBV_TEST -DKBV_MIN_MASTER_LEN=1

HXCRYPT_SRC = hxcrypt/src/blake2s.c hxcrypt/src/chacha20.c \
              hxcrypt/src/csprng.c hxcrypt/src/pbkdf2.c \
              hxcrypt/src/hkdf.c hxcrypt/src/utils.c

KBV_SRC = src/kbv.c platform/kbv_platform_posix.c

.PHONY: test clean

test: test/test_vault.c $(KBV_SRC) $(HXCRYPT_SRC)
	$(CC) $(CFLAGS) -o test_vault $^
	./test_vault
	$(CC) -Wall -Wextra -std=gnu11 -Iinclude -Ihxcrypt/include -DKBV_TEST -o test_master_policy test/test_master_policy.c $(KBV_SRC) $(HXCRYPT_SRC)
	./test_master_policy
	$(CC) -Wall -Wextra -std=gnu11 -Iinclude -o test_rng_health test/test_rng_health.c
	./test_rng_health
	rm -f test_vault test_master_policy test_rng_health vault.bin

clean:
	rm -f test_vault vault.bin
