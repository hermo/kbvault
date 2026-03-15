# kbvault.mk — include this from the QMK keymap's rules.mk
# Assumes kbvault/ is symlinked in the keymap directory.

KBVAULT_DIR := keyboards/$(KEYBOARD)/keymaps/$(KEYMAP)/kbvault

SRC += $(KBVAULT_DIR)/src/kbv.c \
       $(KBVAULT_DIR)/src/rng.c \
       $(KBVAULT_DIR)/platform/kbv_platform_stm32.c \
       $(KBVAULT_DIR)/hxcrypt/src/blake2s.c \
       $(KBVAULT_DIR)/hxcrypt/src/chacha20.c \
       $(KBVAULT_DIR)/hxcrypt/src/csprng.c \
       $(KBVAULT_DIR)/hxcrypt/src/pbkdf2.c \
       $(KBVAULT_DIR)/hxcrypt/src/hkdf.c \
       $(KBVAULT_DIR)/hxcrypt/src/utils.c

EXTRAFLAGS += -I$(KBVAULT_DIR)/include -I$(KBVAULT_DIR)/hxcrypt/include
