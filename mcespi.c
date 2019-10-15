/*
 * MIPS Assembler optimized IPsec cryptographic modules
 *
 * Framework has been taken from Linux kernel source modules aes_generic.c,
 * sha1_generic.c, md5.c and cbc.c. The core functions have been translated
 * to inline assembler for maximum performance.
 *
 * Copyright (c) 2014, Markus Stockhausen <markus.stockhausen@collogia.de>
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2002, Dr Brian Gladman <brg@gladman.me.uk>, Worcester, UK.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) Alan Smithee.
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) Cryptoapi developers.
 *
 * Linux kernel developers:
 *  Alexander Kjeldaas <astor@fast.no>
 *  Herbert Valerio Riedel <hvr@hvrlab.org>
 *  Kyle McMartin <kyle@debian.org>
 *  Adam J. Richter <adam@yggdrasil.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * ---------------------------------------------------------------------------
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * ---------------------------------------------------------------------------
 *
 * mcespi is an MIPS-R2 big endian Linux kernel module for fast AES/SHA1/MD5
 * caluclation. It uses 4K encrpytion and decrpytion tables and aligns them
 * to 1K boundaries for fast offset calculation. If you want to compile it
 * for your Linux kernel do the following:
 *
 * - put mcespi.c into to the crypto/ folder of the kernel
 * - add "obj-$(CONFIG_CRYPTO_MD5) += mcespi.o" to the Makefile in that folder
 * - compile the kernel
 * - finally you should have a mcespi.ko
 *
 * ---------------------------------------------------------------------------
 *
 * Version history
 *
 * 0.1 - 2011/12 test version
 * 0.2 - 2012/02 first official build
 * 0.3 - 2014/08 compilation bugfix thanks to Shuai Xiao
 *
 */

#include <crypto/internal/hash.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <asm/byteorder.h>
#include <linux/debugfs.h>
#include <linux/unaligned/packed_struct.h>

#define NODEBUG

/*
 * ---------------------------------------------------------------------------
 * Debugging Code
 * ---------------------------------------------------------------------------
 */

#ifdef DEBUG

u64 mi_aes_bytes_decrypted;
u64 mi_aes_bytes_encrypted;
u64 mi_sha1_bytes_calculated;
u64 mi_md5_bytes_calculated;
u64 mi_aes_alignment_encrypt[15];
u64 mi_aes_alignment_decrypt[15];

void mi_debug(void)
{
  int i;
  char c[255];
  struct dentry *df;
  struct dentry *dm;

  df = debugfs_create_dir("mcespi", NULL);
  if (!df) return;
/*
 * number of AES decrypted bytes
 */
  dm = debugfs_create_u64("aes_bytes_decrypted", S_IRUGO,
                          df, &mi_aes_bytes_decrypted);
  if (!dm) return;
/*
 * number of aes encrypted bytes
 */
  dm = debugfs_create_u64("aes_bytes_encrypted", S_IRUGO,
                          df, &mi_aes_bytes_encrypted);
  if (!dm) return;
/*
 * number of SHA1 calculated bytes
 */
  dm = debugfs_create_u64("sha1_bytes_calculated", S_IRUGO,
                          df, &mi_sha1_bytes_calculated);
  if (!dm) return;
/*
 * number of MD5 calculated bytes
 */
  dm = debugfs_create_u64("md5_bytes_calculated", S_IRUGO,
                          df, &mi_md5_bytes_calculated);
  if (!dm) return;

  mi_aes_bytes_decrypted = 0;
  mi_aes_bytes_encrypted = 0;
  mi_sha1_bytes_calculated = 0;
  mi_md5_bytes_calculated = 0;

  for (i=0;i<16;i++) {
    mi_aes_alignment_decrypt[i]=0;
    sprintf(c,"aes_alignment_decrypt_%02i",i);
/*
 * AES decrypt input/ouput aligment counters
 */
    dm = debugfs_create_u64(c, S_IRUGO,
                            df, &mi_aes_alignment_decrypt[i]);


    mi_aes_alignment_encrypt[i]=0;
    sprintf(c,"aes_alignment_encrypt_%02i",i);
/*
 * AES encrypt input/ouput aligment counters
 */
    dm = debugfs_create_u64(c, S_IRUGO,
                            df, &mi_aes_alignment_encrypt[i]);
  }
}
#endif

/*
 * ---------------------------------------------------------------------------
 * AES & CBC(AES) Cipher Algorithm
 * ---------------------------------------------------------------------------
 */

#define AES_MIN_KEY_SIZE        16
#define AES_MAX_KEY_SIZE        32
#define AES_KEYSIZE_128         16
#define AES_KEYSIZE_192         24
#define AES_KEYSIZE_256         32
#define AES_BLOCK_SIZE          16
#define AES_MAX_KEYLENGTH       (15 * 16)
#define AES_MAX_KEYLENGTH_U32   (AES_MAX_KEYLENGTH / sizeof(u32))

struct mi_aes_ctx {
/*
 * Just provide a single linear buffer for an AES context. The real
 * start position will be aligned to 8 byte offsets later. It contains
 * the keys for encrpytion and decryption at the following positions:
 *
 * object          postition            length in bytes
 * encryption key: 0                    AES_MAX_KEYLENGTH
 * decrpytion key: AES_MAX_KEYLENGTH    AES_MAX_KEYLENGTH
 * length of key : AES_MAX_KEYLENGTH*2  4
 */
  u32 buffer[AES_MAX_KEYLENGTH_U32*2+1+2]; //dec key,enc key,length,alignment spare
};

static inline u8 byte(const u32 x, const unsigned n)
{
  return x >> (n << 3);
}

static const u32 rco_tab[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };

/*
 * enctab is only the template to fill the the real encryption
 * and decryption table
 */
const u32 mi_aes_enctab[256] = {
  0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6,
  0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
  0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56,
  0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
  0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
  0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
  0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45,
  0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
  0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
  0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
  0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9,
  0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
  0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d,
  0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
  0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
  0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
  0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34,
  0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
  0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d,
  0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
  0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1,
  0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
  0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972,
  0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
  0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
  0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
  0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe,
  0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
  0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05,
  0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
  0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142,
  0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
  0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
  0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
  0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
  0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
  0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3,
  0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
  0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
  0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
  0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14,
  0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
  0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4,
  0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
  0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
  0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
  0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf,
  0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
  0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c,
  0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
  0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
  0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
  0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc,
  0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
  0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
  0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
  0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
  0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
  0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9,
  0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
  0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a,
  0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
  0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
  0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c,
};

/*
 * dectab is only the template to fill the the real encryption
 * and decryption table
 */
const u32 mi_aes_dectab[320] = {
  0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a,
  0xcb6bab3b, 0xf1459d1f, 0xab58faac, 0x9303e34b,
  0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5,
  0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5,
  0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d,
  0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b,
  0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295,
  0x2d83bed4, 0xd3217458, 0x2969e049, 0x44c8c98e,
  0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927,
  0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d,
  0x184adf63, 0x82311ae5, 0x60335197, 0x457f5362,
  0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9,
  0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52,
  0x23d373ab, 0xe2024b72, 0x578f1fe3, 0x2aab5566,
  0x0728ebb2, 0x03c2b52f, 0x9a7bc586, 0xa50837d3,
  0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed,
  0x2b1ccf8a, 0x92b479a7, 0xf0f207f3, 0xa1e2694e,
  0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4,
  0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4,
  0x39ec830b, 0xaaef6040, 0x069f715e, 0x51106ebd,
  0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d,
  0xb58d5491, 0x055dc471, 0x6fd40604, 0xff155060,
  0x24fb9819, 0x97e9bdd6, 0xcc434089, 0x779ed967,
  0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879,
  0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x00000000,
  0x83868009, 0x48ed2b32, 0xac70111e, 0x4e725a6c,
  0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36,
  0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624,
  0xb1670a0c, 0x0fe75793, 0xd296eeb4, 0x9e919b1b,
  0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
  0x0aba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12,
  0x0b0d090e, 0xadc78bf2, 0xb9a8b62d, 0xc8a91e14,
  0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3,
  0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b,
  0x7629438b, 0xdcc623cb, 0x68fcedb6, 0x63f1e4b8,
  0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684,
  0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7,
  0x4b2f9e1d, 0xf330b2dc, 0xec52860d, 0xd0e3c177,
  0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947,
  0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322,
  0xc74e4987, 0xc1d138d9, 0xfea2ca8c, 0x360bd498,
  0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f,
  0xe49d3a2c, 0x0d927850, 0x9bcc5f6a, 0x62467e54,
  0xc2138df6, 0xe8b8d890, 0x5ef7392e, 0xf5afc382,
  0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
  0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb,
  0x097826cd, 0xf418596e, 0x01b79aec, 0xa89a4f83,
  0x656e95e6, 0x7ee6ffaa, 0x08cfbc21, 0xe6e815ef,
  0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029,
  0xafb2a431, 0x31233f2a, 0x3094a5c6, 0xc066a235,
  0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733,
  0x4a9804f1, 0xf7daec41, 0x0e50cd7f, 0x2ff69117,
  0x8dd64d76, 0x4db0ef43, 0x544daacc, 0xdf0496e4,
  0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546,
  0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb,
  0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d,
  0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb,
  0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a,
  0x59dfd29c, 0x3f73f255, 0x79ce1418, 0xbf37c773,
  0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
  0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2,
  0x72c31d16, 0x0c25e2bc, 0x8b493c28, 0x41950dff,
  0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664,
  0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0,

  0x52096ad5, 0x3036a538, 0xbf40a39e, 0x81f3d7fb,
  0x7ce33982, 0x9b2fff87, 0x348e4344, 0xc4dee9cb,
  0x547b9432, 0xa6c2233d, 0xee4c950b, 0x42fac34e,
  0x082ea166, 0x28d924b2, 0x765ba249, 0x6d8bd125,
  0x72f8f664, 0x86689816, 0xd4a45ccc, 0x5d65b692,
  0x6c704850, 0xfdedb9da, 0x5e154657, 0xa78d9d84,
  0x90d8ab00, 0x8cbcd30a, 0xf7e45805, 0xb8b34506,
  0xd02c1e8f, 0xca3f0f02, 0xc1afbd03, 0x01138a6b,
  0x3a911141, 0x4f67dcea, 0x97f2cfce, 0xf0b4e673,
  0x96ac7422, 0xe7ad3585, 0xe2f937e8, 0x1c75df6e,
  0x47f11a71, 0x1d29c589, 0x6fb7620e, 0xaa18be1b,
  0xfc563e4b, 0xc6d27920, 0x9adbc0fe, 0x78cd5af4,
  0x1fdda833, 0x8807c731, 0xb1121059, 0x2780ec5f,
  0x60517fa9, 0x19b54a0d, 0x2de57a9f, 0x93c99cef,
  0xa0e03b4d, 0xae2af5b0, 0xc8ebbb3c, 0x83539961,
  0x172b047e, 0xba77d626, 0xe1691463, 0x55210c7d,
};

/*
 * space for the real enryption table
 */
u32 mi_aes_encdectab[256*9+64];

/*
 * the pointer to the encryption/decryption table
 * it is aligned by 1024 bytes to ensure simple offset
 * calculation with INS assembler commands
 */
u32 *mi_aes_encdec;

/*
 * The following stuff is the usual AES key expanding
 */
#define star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)

#define imix_col(y, x)  do { \
  u  = star_x(x);            \
  v  = star_x(u);            \
  w  = star_x(v);            \
  t  = w ^ (x);              \
  (y)  = u ^ v ^ w;          \
  (y)  ^= ror32(u ^ t, 8) ^  \
  ror32(v ^ t, 16) ^         \
  ror32(t, 24);              \
} while (0)

#define ls_box(x)            \
        ( mi_aes_encdec[byte(x, 0)+512] & 0xff       ) ^ \
        ( mi_aes_encdec[byte(x, 1)+256] & 0xff00     ) ^ \
        ( mi_aes_encdec[byte(x, 2)]     & 0xff0000   ) ^ \
        ( mi_aes_encdec[byte(x, 3)+768] & 0xff000000 )

#define loop4(i)  do {          \
  t = ror32(t, 8);              \
  t = ls_box(t) ^ rco_tab[i];   \
  t ^= key_enc[4 * i];     \
  key_enc[4 * i + 4] = t;  \
  t ^= key_enc[4 * i + 1]; \
  key_enc[4 * i + 5] = t;  \
  t ^= key_enc[4 * i + 2]; \
  key_enc[4 * i + 6] = t;  \
  t ^= key_enc[4 * i + 3]; \
  key_enc[4 * i + 7] = t;  \
} while (0)

#define loop6(i)  do {          \
  t = ror32(t, 8);              \
  t = ls_box(t) ^ rco_tab[i];   \
  t ^= key_enc[6 * i];     \
  key_enc[6 * i + 6] = t;  \
  t ^= key_enc[6 * i + 1]; \
  key_enc[6 * i + 7] = t;  \
  t ^= key_enc[6 * i + 2]; \
  key_enc[6 * i + 8] = t;  \
  t ^= key_enc[6 * i + 3]; \
  key_enc[6 * i + 9] = t;  \
  t ^= key_enc[6 * i + 4]; \
  key_enc[6 * i + 10] = t; \
  t ^= key_enc[6 * i + 5]; \
  key_enc[6 * i + 11] = t; \
} while (0)

#define loop8tophalf(i)  do {   \
  t = ror32(t, 8);              \
  t = ls_box(t) ^ rco_tab[i];   \
  t ^= key_enc[8 * i];     \
  key_enc[8 * i + 8] = t;  \
  t ^= key_enc[8 * i + 1]; \
  key_enc[8 * i + 9] = t;  \
  t ^= key_enc[8 * i + 2]; \
  key_enc[8 * i + 10] = t; \
  t ^= key_enc[8 * i + 3]; \
  key_enc[8 * i + 11] = t; \
} while (0)

#define loop8(i)  do {          \
  loop8tophalf(i);              \
  t  = key_enc[8 * i + 4]  \
     ^ ls_box(t);               \
  key_enc[8 * i + 12] = t; \
  t ^= key_enc[8 * i + 5]; \
  key_enc[8 * i + 13] = t; \
  t ^= key_enc[8 * i + 6]; \
  key_enc[8 * i + 14] = t; \
  t ^= key_enc[8 * i + 7]; \
  key_enc[8 * i + 15] = t; \
} while (0)

int mi_aes_expand_key(struct mi_aes_ctx *ctx, const u8 *in_key,
    unsigned int key_len)
{
  const __le32 *key = (const __le32 *)in_key;
  u32 *key_enc, *key_dec, *key_length;
  u32 i, t, u, v, w, j;

  key_enc   =PTR_ALIGN((void *)ctx,8);
  key_dec   =key_enc+AES_MAX_KEYLENGTH_U32;
  key_length=key_dec+AES_MAX_KEYLENGTH_U32;

  if (key_len != AES_KEYSIZE_128 && key_len != AES_KEYSIZE_192 &&
      key_len != AES_KEYSIZE_256)
    return -EINVAL;

  *key_length = key_len;

  key_dec[key_len + 24] = key_enc[0] = le32_to_cpu(key[0]);
  key_dec[key_len + 25] = key_enc[1] = le32_to_cpu(key[1]);
  key_dec[key_len + 26] = key_enc[2] = le32_to_cpu(key[2]);
  key_dec[key_len + 27] = key_enc[3] = le32_to_cpu(key[3]);

  switch (key_len) {
  case AES_KEYSIZE_128:
    t = key_enc[3];
    for (i = 0; i < 10; ++i)
      loop4(i);
    break;

  case AES_KEYSIZE_192:
    key_enc[4] = le32_to_cpu(key[4]);
    t = key_enc[5] = le32_to_cpu(key[5]);

    for (i = 0; i < 8; ++i)
      loop6(i);
    break;

  case AES_KEYSIZE_256:
    key_enc[4] = le32_to_cpu(key[4]);
    key_enc[5] = le32_to_cpu(key[5]);
    key_enc[6] = le32_to_cpu(key[6]);
    t = key_enc[7] = le32_to_cpu(key[7]);

    for (i = 0; i < 6; ++i)
      loop8(i);
    loop8tophalf(i);
    break;
  }

  key_dec[0] = key_enc[key_len + 24];
  key_dec[1] = key_enc[key_len + 25];
  key_dec[2] = key_enc[key_len + 26];
  key_dec[3] = key_enc[key_len + 27];

  for (i = 4; i < key_len + 24; ++i) {
    j = key_len + 24 - (i & ~3) + (i & 3);
    imix_col(key_dec[j], key_enc[i]);
  }

  for (i=0;i<(key_len+28);i++) {
    key_enc[i] = le32_to_cpu(key_enc[i]);
    key_dec[i] = le32_to_cpu(key_dec[i]);
  }

  return 0;
}

/*
 * mi_aes_set_key() fill the AES context by expanding the
 * given input key into the ecrpytion and decryption part
 */
int mi_aes_set_key(struct crypto_tfm *tfm, const u8 *in_key,
    unsigned int key_len)
{
  struct mi_aes_ctx *ctx = crypto_tfm_ctx(tfm);
  u32 *flags = &tfm->crt_flags;
  int ret;
  //int i;

  ret = mi_aes_expand_key(ctx, in_key, key_len);
  if (!ret)
    return 0;

  *flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
  return -EINVAL;
}

/*
 * mi_cbc_encrypt_segment() does the CBC(AES) encryption of one data
 * segment. As CBC is only a simple XOR operation after the AES cycles
 * we will handle it in the same function to save function calls and
 * initialization
 */
void mi_cbc_encrypt_segment(struct crypto_tfm *tfm,
                         u8 *out, const u8 *in, unsigned int nbytes, u8 *iv)

{
  struct mi_aes_ctx *ctx = (struct mi_aes_ctx *)PTR_ALIGN(crypto_tfm_ctx(tfm),8);
  u32 *encdec = mi_aes_encdec;

#ifdef DEBUG
/*
 * increase debug information about alignment of input and ouput data
 */
  int i;
  i=(u32)in & 0xf;
  mi_aes_alignment_encrypt[i]++;

  i=(u32)out & 0xf;
  mi_aes_alignment_encrypt[i]++;
#endif

  __asm__ (
    ".set noat;"
/*
 * Set register S1 to the end of the encryption key. It is
 * the stop offset for our calculations
 */
    "lw    $s0,%2;"
    "lw    $s1,%4($s0);"
    "sll   $s1,$s1,2;"
    "addiu $s1,$s1,80;"
    "addu  $s1,$s1,$s0;"
/*
 * The pointers to data. S2 = source data, S3 = encrypted data
 * AT is the end of the input data
 */
    "lw    $s2,%0;"
    "lw    $s3,%1;"

    "lw    $t1,%6;"
    "addiu $t0,$zero,-16;"
    "and   $t1,$t1,$t0;"
    "addu  $at,$s2,$t1;"
/*
 * A0 - A4 contain pointers to the encryption table
 * Because it is aligned to 1024 bytes we can insert data
 * to bits 2-9 and get the offset of an element in that table
 */
    "lw    $a0,%3;              lw    $a1,%3;"
    "lw    $a2,%3;              lw    $a3,%3;"
/*
 * S4 - S7 contain the initialization vector. That means the
 * last encrypted block that we use to XOR the current block
 * after the AES loop
 */
    "lw    $t5,%5;"
    "ld    $s4,0($t5);"
    "ld    $s6,8($t5);"
/*
 * main loop over all data
 */
    "cbc_enc_main%=:;"
/*
 * set S0 to the start of the encryption key
 */
      "lw    $s0,%2;"
/*
 * load the next input data. we allow unaligend input to avoid
 * copy operations to aligned data.
 */
      "lwl   $t0,0($s2);          lwl   $t1,4($s2);"
      "lwl   $t2,8($s2);          lwl   $t3,12($s2);"
      "lwr   $t0,3($s2);          lwr   $t1,7($s2);"
      "lwr   $t2,11($s2);         lwr   $t3,15($s2);"
/*
 * XOR data with the last encrypted block (CBC)
 */
      "xor   $t0,$t0,$s4;"
      "xor   $t1,$t1,$s5;"
      "xor   $t2,$t2,$s6;"
      "xor   $t3,$t3,$s7;"
/*
 * Initialize working registers with keys and data. Algorithm
 * runs on T0 - T7 and V0 - V7
 */
      "ld    $t4,0($s0);          ld    $t6,8($s0);"
      "xor   $t0,$t0,$t4;         xor   $t1,$t1,$t5;"
      "xor   $t2,$t2,$t6;         xor   $t3,$t3,$t7;"
/*
 * Standard AES encrpytion loop
 */
      "cbc_enc_loop%=:;"

        "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
        "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
        "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
        "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
        "lw    $t5,3072($a0);       lw    $t6,3072($a1);"
        "lw    $t7,3072($a2);       lw    $t4,3072($a3);"

        "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
        "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
        "srl   $t1,$t1,8;           srl   $t2,$t2,8;"
        "srl   $t3,$t3,8;           srl   $t0,$t0,8;"
        "lw    $v0,2048($a2);       lw    $v1,2048($a3);"
        "lw    $t8,2048($a0);       lw    $t9,2048($a1);"
        "xor   $t4,$t4,$v0;         xor   $t5,$t5,$v1;"
        "xor   $t6,$t6,$t8;         xor   $t7,$t7,$t9;"

        "ins   $a1,$t1,2,8;         ins   $a2,$t2,2,8;"
        "ins   $a3,$t3,2,8;         ins   $a0,$t0,2,8;"
        "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
        "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
        "lw    $t9,1024($a1);       lw    $v0,1024($a2);"
        "lw    $v1,1024($a3);       lw    $t8,1024($a0);"
        "xor   $t4,$t4,$t9;         xor   $t5,$t5,$v0;"
        "xor   $t6,$t6,$v1;         xor   $t7,$t7,$t8;"
/*
 * increase pointer to encryption key
 */
        "addiu $s0,$s0,16;"

        "ins   $a3,$t3,2,8;         ins   $a0,$t0,2,8;"
        "ins   $a1,$t1,2,8;         ins   $a2,$t2,2,8;"
        "lw    $v1,0($a3);          lw    $t8,0($a0);"
        "lw    $t9,0($a1);          lw    $v0,0($a2);"
        "xor   $t0,$t4,$t8;         xor   $t1,$t5,$t9;"
        "xor   $t2,$t6,$v0;         xor   $t3,$t7,$v1;"

        "ld    $t4,0($s0);          ld    $t6,8($s0);"

 	    "xor   $t0,$t0,$t4;         xor   $t1,$t1,$t5;"
        "xor   $t2,$t2,$t6;         xor   $t3,$t3,$t7;"
/*
 * run AES loop until we reach the end of the encrpytion key
 */
      "bne   $s1,$s0,cbc_enc_loop%=;"
/*
 * The last encrpytion operations outside the loop
 */
      "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
      "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
      "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
      "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
      "lbu   $t5,2048($a0);       lbu   $t6,2048($a1);"
      "lbu   $t7,2048($a2);       lbu   $t4,2048($a3);"

      "ins   $a1,$t1,2,8;         ins   $a2,$t2,2,8;"
      "ins   $a3,$t3,2,8;         ins   $a0,$t0,2,8;"
      "srl   $t1,$t1,8;           srl   $t2,$t2,8;"
      "srl   $t3,$t3,8;           srl   $t0,$t0,8;"
      "lbu   $t9,2048($a1);       lbu   $v0,2048($a2);"
      "lbu   $v1,2048($a3);       lbu   $t8,2048($a0);"
      "ins   $t4,$v0,8,8;         ins   $t5,$v1,8,8;"
      "ins   $t6,$t8,8,8;         ins   $t7,$t9,8,8;"

      "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
      "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
      "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
      "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
      "lbu   $v0,2048($a2);       lbu   $v1,2048($a3);"
      "lbu   $t8,2048($a0);       lbu   $t9,2048($a1);"
      "ins   $t6,$v1,16,8;        ins   $t7,$t8,16,8;"
      "ins   $t4,$t9,16,8;        ins   $t5,$v0,16,8;"

      "ins   $a3,$t3,2,8;         ins   $a0,$t0,2,8;"
      "ins   $a1,$t1,2,8;         ins   $a2,$t2,2,8;"
      "lbu   $v1,2048($a3);       lbu   $t8,2048($a0);"
      "lbu   $t9,2048($a1);       lbu   $v0,2048($a2);"
      "ins   $t4,$t8,24,8;        ins   $t5,$t9,24,8;"
      "ins   $t6,$v0,24,8;        ins   $t7,$v1,24,8;"

      "ld    $t0,16($s0);         ld    $t2,24($s0);"
      "xor   $s4,$t0,$t4;         xor   $s5,$t1,$t5;"
      "xor   $s6,$t2,$t6;         xor   $s7,$t3,$t7;"
/*
 * AES encrpytion has finished. Result is in register S4 - S7
 * store it (unaligend) into the destination memory area
 */
      "swl   $s4,0($s3);          swl   $s5,4($s3);"
      "swl   $s6,8($s3);          swl   $s7,12($s3);"
      "swr   $s4,3($s3);          swr   $s5,7($s3);"
      "swr   $s6,11($s3);         swr   $s7,15($s3);"
/*
 * increase source and destination pointers
 */
      "addiu $s2,$s2,16;"
      "addiu $s3,$s3,16;"
/*
 * run the loop until the end of the data
 */
    "bne   $at,$s2,cbc_enc_main%=;"
/*
 * finally store initialization vector in memory area of caller
 * for next call to this function
 */
    "lw    $t5,%5;"
    "sd    $s4,0($t5);"
    "sd    $s6,8($t5);"

    :
    : "m"(in),
      "m"(out),
      "m"(ctx),
      "m"(encdec),
      "i"(AES_MAX_KEYLENGTH_U32*8),
      "m"(iv),
      "m"(nbytes)
    : "a0","a1","a2","a3",
      "t0","t1","t2","t3","t4","t5","t6","t7","t8","t9",
      "v0","v1",
      "s0","s1","s2","s3","s4","s5","s6","s7" );

#ifdef DEBUG
/*
 * increase information about number of encrypted bytes
 */
  mi_aes_bytes_encrypted += (u64)nbytes;
#endif
}

/*
 * mi_aes_encrypt() encrypts only a single 128 bit (16 byte) block of data
 */
static void mi_aes_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
  volatile u32 iv[4];
  iv[0]=0; iv[1]=0; iv[2]=0; iv[3]=0;
/*
 * AES is nothing more than CBC(AES) with init vector of zero
 * so reuse our generic function
 */
  mi_cbc_encrypt_segment(tfm,out,in,AES_BLOCK_SIZE,(u8 *)iv);
}

/*
 * mi_cbc_encrypt() encrpyts several data segments. For each segment
 * it calls mi_cbc_encrypt_segment() and hands over the initialization
 * vector
 */
 static int mi_cbc_encrypt(struct blkcipher_desc *desc,
                          struct scatterlist *dst,
                          struct scatterlist *src,
                          unsigned int nbytes)
{
  struct blkcipher_walk walk;
  struct crypto_tfm *tfm = (struct crypto_tfm *)desc->tfm;
  int err;

  blkcipher_walk_init(&walk, dst, src, nbytes);
  err = blkcipher_walk_virt(desc, &walk);

  while ((nbytes = walk.nbytes)) {
    mi_cbc_encrypt_segment(tfm,walk.dst.virt.addr,
                           walk.src.virt.addr,nbytes,walk.iv);
    nbytes &= AES_BLOCK_SIZE - 1;
    err = blkcipher_walk_done(desc, &walk, nbytes);
  }

  return err;
}

/*
 * mi_cbc_decrypt_segment() does the CBC(AES) decryption of one data
 * segment. As CBC is only a simple XOR operation after the AES cycles
 * we will handle it in the same function to save function calls and
 * initialization
 */
void mi_cbc_decrypt_segment(struct crypto_tfm *tfm,
                         u8 *out, const u8 *in, unsigned int nbytes, u8 *iv)

{
  struct mi_aes_ctx *ctx = (struct mi_aes_ctx *)PTR_ALIGN(crypto_tfm_ctx(tfm),8);
  u32 *encdec = mi_aes_encdec;

#ifdef DEBUG
/*
 * increase debug information about alignment of input and ouput data
 */
  int i;
  i=(u32)in & 0xf;
  mi_aes_alignment_decrypt[i]++;

  i=(u32)out & 0xf;
  mi_aes_alignment_decrypt[i]++;
#endif

  __asm__ (
    ".set noat;"
/*
 * S1 points to the end of the decryption key
 */
    "lw    $s0,%2;"
    "addiu $s0,$s0,%4;"
    "lw    $s1,%4($s0);"
    "sll   $s1,$s1,2;"
    "addiu $s1,$s1,80;"
    "addu  $s1,$s1,$s0;"
/*
 * we will descend the data from end to start so set
 * the endpointer to the beginning of the input
 */
    "lw    $at,%0;"
/*
 * S2 is pointer to input data and S3 points to output
 * data. We will start at the end of the data
 */
    "lw    $s3,%1;"
    "lw    $t1,%6;"
    "addiu $t0,$zero,-16;"
    "and   $t1,$t1,$t0;"
    "addiu $t1,$t1,-16;"
    "addu  $s3,$s3,$t1;"
    "addu  $s2,$at,$t1;"
/*
 * load pointer to AES encryption table into A0 - A3
 */
    "lw    $a0,%3;              lw    $a1,%3;"
    "lw    $a2,%3;              lw    $a3,%3;"


/* Fill S4 - S7 with last initialization vector
 * Fill T0 - T3 with input data
 */
    "lw    $t5,%5;"
    "lwl   $t0,0($s2);          lwl   $t1,4($s2);"
    "lwl   $t2,8($s2);          lwl   $t3,12($s2);"
    "lwr   $t0,3($s2);          lwr   $t1,7($s2);"
    "lwr   $t2,11($s2);         lwr   $t3,15($s2);"
    "ld    $s4,0($t5);"
    "ld    $s6,8($t5);"
    "sd    $t0,0($t5);"
    "sd    $t2,8($t5);"
/*
 * The main loop over all data
 */
    "cbc_main_loop%=:;"
/*
 * Fill S0 with pointer do decryption key
 */
      "lw    $s0,%2;"
      "addiu $s0,$s0,%4;"

      "ld    $t4,0($s0);          ld    $t6,8($s0);"
      "xor   $t0,$t0,$t4;         xor   $t1,$t1,$t5;"
      "xor   $t2,$t2,$t6;         xor   $t3,$t3,$t7;"
      "ins   $a0,$zero,0,10;      ins   $a1,$zero,0,10;"
      "ins   $a2,$zero,0,10;      ins   $a3,$zero,0,10;"
/*
 * The AES decryption loop
 */
      "cbc_dec_loop%=:;"

        "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
        "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
        "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
        "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
        "lw    $t7,7168($a0);       lw    $t4,7168($a1);"
        "lw    $t5,7168($a2);       lw    $t6,7168($a3);"

        "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
        "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
        "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
        "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
        "lw    $v1,6144($a3);       lw    $t8,6144($a0);"
        "lw    $t9,6144($a1);       lw    $v0,6144($a2);"
        "xor   $t4,$t4,$v0;         xor   $t5,$t5,$v1;"
        "xor   $t6,$t6,$t8;         xor   $t7,$t7,$t9;"

        "ins   $a0,$t0,2,8;         ins   $a1,$t1,2,8;"
        "ins   $a2,$t2,2,8;         ins   $a3,$t3,2,8;"
        "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
        "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
        "lw    $v0,5120($a2);       lw    $v1,5120($a3);"
        "lw    $t8,5120($a0);       lw    $t9,5120($a1);"
        "xor   $t4,$t4,$v1;         xor   $t5,$t5,$t8;"
        "xor   $t6,$t6,$t9;         xor   $t7,$t7,$v0;"
/*
 * increase pointer to decryption key
 */
        "addiu $s0,$s0,16;"

        "ins   $a1,$t1,2,8;         ins   $a2,$t2,2,8;"
        "ins   $a3,$t3,2,8;         ins   $a0,$t0,2,8;"
        "lw    $t9,4096($a1);       lw    $v0,4096($a2);"
        "lw    $v1,4096($a3);       lw    $t8,4096($a0);"
        "xor   $t0,$t4,$t8;         xor   $t1,$t5,$t9;"
        "xor   $t2,$t6,$v0;         xor   $t3,$t7,$v1;"

        "ld    $t4,0($s0);          ld    $t6,8($s0);"
        "xor   $t0,$t0,$t4;         xor   $t1,$t1,$t5;"
        "xor   $t2,$t2,$t6;         xor   $t3,$t3,$t7;"
/*
 * loop until end of key
 */
      "bne   $s1,$s0,cbc_dec_loop%=;"
/*
 * do the rest of the AES decryption
 */
      "ins   $a0,$zero,0,10;      ins   $a1,$zero,0,10;"
      "ins   $a2,$zero,0,10;      ins   $a3,$zero,0,10;"

      "ins   $a0,$t0,0,8;         ins   $a1,$t1,0,8;"
      "ins   $a2,$t2,0,8;         ins   $a3,$t3,0,8;"
      "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
      "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
      "lbu   $t7,8192($a0);       lbu   $t4,8192($a1);"
      "lbu   $t5,8192($a2);       lbu   $t6,8192($a3);"

      "ins   $a1,$t1,0,8;         ins   $a2,$t2,0,8;"
      "ins   $a3,$t3,0,8;         ins   $a0,$t0,0,8;"
      "srl   $t1,$t1,8;           srl   $t2,$t2,8;"
      "srl   $t3,$t3,8;           srl   $t0,$t0,8;"
      "lbu   $t9,8192($a1);       lbu   $v0,8192($a2);"
      "lbu   $v1,8192($a3);       lbu   $t8,8192($a0);"
      "ins   $t4,$v0,8,8;         ins   $t5,$v1,8,8;"
      "ins   $t6,$t8,8,8;         ins   $t7,$t9,8,8;"

      "ins   $a0,$t0,0,8;         ins   $a1,$t1,0,8;"
      "ins   $a2,$t2,0,8;         ins   $a3,$t3,0,8;"
      "srl   $t0,$t0,8;           srl   $t1,$t1,8;"
      "srl   $t2,$t2,8;           srl   $t3,$t3,8;"
      "lbu   $v0,8192($a2);       lbu   $v1,8192($a3);"
      "lbu   $t8,8192($a0);       lbu   $t9,8192($a1);"
      "ins   $t4,$v1,16,8;        ins   $t5,$t8,16,8;"
      "ins   $t6,$t9,16,8;        ins   $t7,$v0,16,8;"

      "ins   $a3,$t3,0,8;         ins   $a0,$t0,0,8;"
      "ins   $a1,$t1,0,8;         ins   $a2,$t2,0,8;"
      "lbu   $v1,8192($a3);       lbu   $t8,8192($a0);"
      "lbu   $t9,8192($a1);       lbu   $v0,8192($a2);"
      "ins   $t4,$t8,24,8;        ins   $t5,$t9,24,8;"
      "ins   $t6,$v0,24,8;        ins   $t7,$v1,24,8;"

      "ld    $t0,16($s0);         ld    $t2,24($s0);"
      "xor   $t4,$t0,$t4;         xor   $t5,$t1,$t5;"
      "xor   $t6,$t2,$t6;         xor   $t7,$t3,$t7;"
/*
 * kick out of we are at end of data
 */
      "beq   $s2,$at,cbc_end%=;"
/*
 * decrease pointer to input data
 */
      "addiu $s2,$s2,-16;"
/*
 * The AES loop finished. Data is decrypted in T4 - T7. But not yet
 * scored. So we load the next encrypted data block into T0 - T3
 * and to the CBC xoring
 */
      "lwl   $t0,0($s2);          lwl   $t1,4($s2);"
      "lwl   $t2,8($s2);          lwl   $t3,12($s2);"
      "lwr   $t0,3($s2);          lwr   $t1,7($s2);"
      "lwr   $t2,11($s2);         lwr   $t3,15($s2);"

      "xor   $t4,$t0,$t4;"
      "xor   $t5,$t1,$t5;"
      "xor   $t6,$t2,$t6;"
      "xor   $t7,$t3,$t7;"
/*
 * Store descrypted output data finally
 */
      "swl   $t4,0($s3);          swl   $t5,4($s3);"
      "swl   $t6,8($s3);          swl   $t7,12($s3);"
      "swr   $t4,3($s3);          swr   $t5,7($s3);"
      "swr   $t6,11($s3);         swr   $t7,15($s3);"
/*
 * advance with output pointer
 */
      "addiu $s3,$s3,-16;"

    "j cbc_main_loop%=;"

    "cbc_end%=:;"
/*
 * Finally XOR the first data block with the provided
 * initialization vector in S4 - S7
 */
    "xor   $t4,$s4,$t4;"
    "xor   $t5,$s5,$t5;"
    "xor   $t6,$s6,$t6;"
    "xor   $t7,$s7,$t7;"
/*
 * And store the first block
 */
    "sd    $t4,0($s3);"
    "sd    $t6,8($s3);"

    :
    : "m"(in),
      "m"(out),
      "m"(ctx),
      "m"(encdec),
      "i"(AES_MAX_KEYLENGTH_U32*4),
      "m"(iv),
      "m"(nbytes)
    : "a0","a1","a2","a3","at",
      "t0","t1","t2","t3","t4","t5","t6","t7","t8","t9",
      "v0","v1",
      "s0","s1","s2","s3","s4","s5","s6","s7" );

#ifdef DEBUG
/*
 * increase information about number of decrypted bytes
 */
  mi_aes_bytes_decrypted += (u64)nbytes;
#endif

}

/*
 * mi_aes_decrypt() descrpyts a single 128 bit (16 byte) data block
 */
static void mi_aes_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
  volatile u32 iv[4];
  iv[0]=0; iv[1]=0; iv[2]=0; iv[3]=0;

/*
 * we just run the CBC(AES) decryption function with intialization
 * vector of zero
 */
  mi_cbc_decrypt_segment(tfm,out,in,AES_BLOCK_SIZE,(u8 *)iv);
}

/*
 * run CBC(AES) decryption over several segments
 */
static int mi_cbc_decrypt(struct blkcipher_desc *desc,
                          struct scatterlist *dst,
                          struct scatterlist *src,
                          unsigned int nbytes)
{
  struct blkcipher_walk walk;
  struct crypto_tfm *tfm = (struct crypto_tfm *)desc->tfm;
  int err;

  blkcipher_walk_init(&walk, dst, src, nbytes);
  err = blkcipher_walk_virt(desc, &walk);

  while ((nbytes = walk.nbytes)) {
    mi_cbc_decrypt_segment(tfm,walk.dst.virt.addr,
                           walk.src.virt.addr,nbytes,walk.iv);
    nbytes &= AES_BLOCK_SIZE - 1;
    err = blkcipher_walk_done(desc, &walk, nbytes);
  }

  return err;
}

/*
 * do the algorithm registration
 */
static struct crypto_alg mi_aes_alg = {
  .cra_name         = "aes",
  .cra_driver_name  = "aes-mcespi",
  .cra_priority     = 200,
  .cra_flags        = CRYPTO_ALG_TYPE_CIPHER,
  .cra_blocksize    = AES_BLOCK_SIZE,
  .cra_ctxsize      = sizeof(struct mi_aes_ctx),
  .cra_alignmask    = 0,
  .cra_module       = THIS_MODULE,
  .cra_list         = LIST_HEAD_INIT(mi_aes_alg.cra_list),
  .cra_u            = {
    .cipher           = {
      .cia_min_keysize  = AES_MIN_KEY_SIZE,
      .cia_max_keysize  = AES_MAX_KEY_SIZE,
      .cia_setkey       = mi_aes_set_key,
      .cia_encrypt      = mi_aes_encrypt,
      .cia_decrypt      = mi_aes_decrypt
    }
  }
};

static struct crypto_alg mi_cbc_alg = {
  .cra_name               = "cbc(aes)",
  .cra_driver_name        = "cbc-mcespi",
  .cra_priority           = 300,
  .cra_flags              = CRYPTO_ALG_TYPE_BLKCIPHER,
  .cra_blocksize          = AES_BLOCK_SIZE,
  .cra_ctxsize            = sizeof(struct mi_aes_ctx),
  .cra_alignmask          = 0,
  .cra_type               = &crypto_blkcipher_type,
  .cra_module             = THIS_MODULE,
  .cra_list               = LIST_HEAD_INIT(mi_cbc_alg.cra_list),
  .cra_u = {
    .blkcipher = {
      .min_keysize    = AES_MIN_KEY_SIZE,
      .max_keysize    = AES_MAX_KEY_SIZE,
      .ivsize         = AES_BLOCK_SIZE,
      .setkey         = mi_aes_set_key,
      .encrypt        = mi_cbc_encrypt,
      .decrypt        = mi_cbc_decrypt,
    }
  }
};

/*
 * ---------------------------------------------------------------------------
 * SHA1 Secure Hash Algorithm
 * ---------------------------------------------------------------------------
 */

#define SHA1_DIGEST_SIZE    20
#define SHA1_BLOCK_SIZE     64
#define SHA_WORKSPACE_WORDS 16

struct mi_sha1_ctx {
  u64 count;
  u32 state[SHA1_DIGEST_SIZE / 4];
  u8 buffer[SHA1_BLOCK_SIZE];
};

/*
 * mi_sha1_transform()
 */
void static mi_sha1_transform(__u32 *digest, const char *data)
{
  __asm__ volatile (
    ".set noat;"
    ".set noreorder;"

/*
 * load old 160 bit (20 byte) SHA1 value into S0-S4
 */
    "lw $s7,%0;"
    "lw $s0,0($s7);"
    "lw $s1,4($s7);"
    "lw $s2,8($s7);"
    "lw $s3,12($s7);"
    "lw $s4,16($s7);"
/*
 * Load 512 bit (64 byte) input data
 */
    "lw  $s7,%1;"
    "lwl $t0,0($s7);"
    "lwl $t1,4($s7);"
    "lwl $t2,8($s7);"
    "lwl $t3,12($s7);"
    "lwl $t4,16($s7);"
    "lwl $t5,20($s7);"
    "lwl $t6,24($s7);"
    "lwl $t7,28($s7);"
    "lwl $t8,32($s7);"
    "lwl $t9,36($s7);"
    "lwl $a0,40($s7);"
    "lwl $a1,44($s7);"
    "lwl $a2,48($s7);"
    "lwl $a3,52($s7);"
    "lwl $v0,56($s7);"
    "lwl $v1,60($s7);"

    "lwr $t0,3($s7);"
    "lwr $t1,7($s7);"
    "lwr $t2,11($s7);"
    "lwr $t3,15($s7);"
    "lwr $t4,19($s7);"
    "lwr $t5,23($s7);"
    "lwr $t6,27($s7);"
    "lwr $t7,31($s7);"
    "lwr $t8,35($s7);"
    "lwr $t9,39($s7);"
    "lwr $a0,43($s7);"
    "lwr $a1,47($s7);"
    "lwr $a2,51($s7);"
    "lwr $a3,55($s7);"
    "lwr $v0,59($s7);"
    "lwr $v1,63($s7);"

/*
 * T00-T15
 */
    "lui $at,0x5a82;"
    "ori $at,$at,0x7999;"

    "rotr  $s6,$s0,27;          addu  $s4,$s4,$t0;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         and   $s7,$s7,$s1;         addu  $s4,$s4,$at;"
    "xor   $s7,$s7,$s3;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "rotr  $s6,$s4,27;          addu  $s3,$s3,$t1;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         and   $s7,$s7,$s0;         addu  $s3,$s3,$at;"
    "xor   $s7,$s7,$s2;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "rotr  $s6,$s3,27;          addu  $s2,$s2,$t2;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         and   $s7,$s7,$s4;         addu  $s2,$s2,$at;"
    "xor   $s7,$s7,$s1;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "rotr  $s6,$s2,27;          addu  $s1,$s1,$t3;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         and   $s7,$s7,$s3;         addu  $s1,$s1,$at;"
    "xor   $s7,$s7,$s0;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "rotr  $s6,$s1,27;          addu  $s0,$s0,$t4;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         and   $s7,$s7,$s2;         addu  $s0,$s0,$at;"
    "xor   $s7,$s7,$s4;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"
    "rotr  $s6,$s0,27;          addu  $s4,$s4,$t5;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         and   $s7,$s7,$s1;         addu  $s4,$s4,$at;"
    "xor   $s7,$s7,$s3;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "rotr  $s6,$s4,27;          addu  $s3,$s3,$t6;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         and   $s7,$s7,$s0;         addu  $s3,$s3,$at;"
    "xor   $s7,$s7,$s2;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"

    "rotr  $s6,$s3,27;          addu  $s2,$s2,$t7;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         and   $s7,$s7,$s4;         addu  $s2,$s2,$at;"
    "xor   $s7,$s7,$s1;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "rotr  $s6,$s2,27;          addu  $s1,$s1,$t8;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         and   $s7,$s7,$s3;         addu  $s1,$s1,$at;"
    "xor   $s7,$s7,$s0;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "rotr  $s6,$s1,27;          addu  $s0,$s0,$t9;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         and   $s7,$s7,$s2;         addu  $s0,$s0,$at;"
    "xor   $s7,$s7,$s4;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"
    "rotr  $s6,$s0,27;          addu  $s4,$s4,$a0;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         and   $s7,$s7,$s1;         addu  $s4,$s4,$at;"
    "xor   $s7,$s7,$s3;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "rotr  $s6,$s4,27;          addu  $s3,$s3,$a1;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         and   $s7,$s7,$s0;         addu  $s3,$s3,$at;"
    "xor   $s7,$s7,$s2;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "rotr  $s6,$s3,27;          addu  $s2,$s2,$a2;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         and   $s7,$s7,$s4;         addu  $s2,$s2,$at;"
    "xor   $s7,$s7,$s1;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "rotr  $s6,$s2,27;          addu  $s1,$s1,$a3;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         and   $s7,$s7,$s3;         addu  $s1,$s1,$at;"
    "xor   $s7,$s7,$s0;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "rotr  $s6,$s1,27;          addu  $s0,$s0,$v0;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         and   $s7,$s7,$s2;         addu  $s0,$s0,$at;"
    "xor   $s7,$s7,$s4;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"
    "rotr  $s6,$s0,27;          addu  $s4,$s4,$v1;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         and   $s7,$s7,$s1;         addu  $s4,$s4,$at;"
    "xor   $s7,$s7,$s3;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
/*
 * T16-T19
 */
    "addu  $s3,$s3,$at;         xor   $t0,$t0,$t2;         xor   $s5,$t8,$a3;"
    "rotr  $s6,$s4,27;          xor   $t0,$t0,$s5;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         rotr  $t0,$t0,31;          and   $s7,$s7,$s0;"
    "addu  $s3,$s3,$t0;         xor   $s7,$s7,$s2;         rotr  $s0,$s0,2;"
    "addu  $s3,$s3,$s7;"

    "addu  $s2,$s2,$at;         xor   $t1,$t1,$t3;         xor   $s5,$t9,$v0;"
    "rotr  $s6,$s3,27;          xor   $t1,$t1,$s5;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         rotr  $t1,$t1,31;          and   $s7,$s7,$s4;"
    "addu  $s2,$s2,$t1;         xor   $s7,$s7,$s1;         rotr  $s4,$s4,2;"
    "addu  $s2,$s2,$s7;"

    "addu  $s1,$s1,$at;         xor   $t2,$t2,$t4;         xor   $s5,$a0,$v1;"
    "rotr  $s6,$s2,27;          xor   $t2,$t2,$s5;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         rotr  $t2,$t2,31;          and   $s7,$s7,$s3;"
    "addu  $s1,$s1,$t2;         xor   $s7,$s7,$s0;         rotr  $s3,$s3,2;"
    "addu  $s1,$s1,$s7;"

    "addu  $s0,$s0,$at;         xor   $t3,$t3,$t5;         xor   $s5,$a1,$t0;"
    "rotr  $s6,$s1,27;          xor   $t3,$t3,$s5;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         rotr  $t3,$t3,31;          and   $s7,$s7,$s2;"
    "addu  $s0,$s0,$t3;         xor   $s7,$s7,$s4;         rotr  $s2,$s2,2;"
    "addu  $s0,$s0,$s7;"
/*
 * T20-T39
 */
    "lui $at,0x6ed9;"
    "ori $at,$at,0xeba1;"

    "sha1_redo%=:;"

    "addu  $s4,$s4,$at;         xor   $t4,$t4,$t6;         xor   $s5,$a2,$t1;"
    "rotr  $s6,$s0,27;          xor   $t4,$t4,$s5;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         rotr  $t4,$t4,31;          xor   $s7,$s7,$s1;"
    "addu  $s4,$s4,$t4;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "addu  $s3,$s3,$at;         xor   $t5,$t5,$t7;         xor   $s5,$a3,$t2;"
    "rotr  $s6,$s4,27;          xor   $t5,$t5,$s5;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         rotr  $t5,$t5,31;          xor   $s7,$s7,$s0;"
    "addu  $s3,$s3,$t5;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "addu  $s2,$s2,$at;         xor   $t6,$t6,$t8;         xor   $s5,$v0,$t3;"
    "rotr  $s6,$s3,27;          xor   $t6,$t6,$s5;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         rotr  $t6,$t6,31;          xor   $s7,$s7,$s4;"
    "addu  $s2,$s2,$t6;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "addu  $s1,$s1,$at;         xor   $t7,$t7,$t9;         xor   $s5,$v1,$t4;"
    "rotr  $s6,$s2,27;          xor   $t7,$t7,$s5;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         rotr  $t7,$t7,31;          xor   $s7,$s7,$s3;"
    "addu  $s1,$s1,$t7;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "addu  $s0,$s0,$at;         xor   $t8,$t8,$a0;         xor   $s5,$t0,$t5;"
    "rotr  $s6,$s1,27;          xor   $t8,$t8,$s5;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         rotr  $t8,$t8,31;          xor   $s7,$s7,$s2;"
    "addu  $s0,$s0,$t8;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"

    "addu  $s4,$s4,$at;         xor   $t9,$t9,$a1;         xor   $s5,$t1,$t6;"
    "rotr  $s6,$s0,27;          xor   $t9,$t9,$s5;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         rotr  $t9,$t9,31;          xor   $s7,$s7,$s1;"
    "addu  $s4,$s4,$t9;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "addu  $s3,$s3,$at;         xor   $a0,$a0,$a2;         xor   $s5,$t2,$t7;"
    "rotr  $s6,$s4,27;          xor   $a0,$a0,$s5;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         rotr  $a0,$a0,31;          xor   $s7,$s7,$s0;"
    "addu  $s3,$s3,$a0;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "addu  $s2,$s2,$at;         xor   $a1,$a1,$a3;         xor   $s5,$t3,$t8;"
    "rotr  $s6,$s3,27;          xor   $a1,$a1,$s5;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         rotr  $a1,$a1,31;          xor   $s7,$s7,$s4;"
    "addu  $s2,$s2,$a1;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "addu  $s1,$s1,$at;         xor   $a2,$a2,$v0;         xor   $s5,$t4,$t9;"
    "rotr  $s6,$s2,27;          xor   $a2,$a2,$s5;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         rotr  $a2,$a2,31;          xor   $s7,$s7,$s3;"
    "addu  $s1,$s1,$a2;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "addu  $s0,$s0,$at;         xor   $a3,$a3,$v1;         xor   $s5,$t5,$a0;"
    "rotr  $s6,$s1,27;          xor   $a3,$a3,$s5;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         rotr  $a3,$a3,31;          xor   $s7,$s7,$s2;"
    "addu  $s0,$s0,$a3;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"

    "addu  $s4,$s4,$at;         xor   $v0,$v0,$t0;         xor   $s5,$t6,$a1;"
    "rotr  $s6,$s0,27;          xor   $v0,$v0,$s5;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         rotr  $v0,$v0,31;          xor   $s7,$s7,$s1;"
    "addu  $s4,$s4,$v0;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "addu  $s3,$s3,$at;         xor   $v1,$v1,$t1;         xor   $s5,$t7,$a2;"
    "rotr  $s6,$s4,27;          xor   $v1,$v1,$s5;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         rotr  $v1,$v1,31;          xor   $s7,$s7,$s0;"
    "addu  $s3,$s3,$v1;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "addu  $s2,$s2,$at;         xor   $t0,$t0,$t2;         xor   $s5,$t8,$a3;"
    "rotr  $s6,$s3,27;          xor   $t0,$t0,$s5;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         rotr  $t0,$t0,31;          xor   $s7,$s7,$s4;"
    "addu  $s2,$s2,$t0;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "addu  $s1,$s1,$at;         xor   $t1,$t1,$t3;         xor   $s5,$t9,$v0;"
    "rotr  $s6,$s2,27;          xor   $t1,$t1,$s5;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         rotr  $t1,$t1,31;          xor   $s7,$s7,$s3;"
    "addu  $s1,$s1,$t1;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "addu  $s0,$s0,$at;         xor   $t2,$t2,$t4;         xor   $s5,$a0,$v1;"
    "rotr  $s6,$s1,27;          xor   $t2,$t2,$s5;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         rotr  $t2,$t2,31;          xor   $s7,$s7,$s2;"
    "addu  $s0,$s0,$t2;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"

    "addu  $s4,$s4,$at;         xor   $t3,$t3,$t5;         xor   $s5,$a1,$t0;"
    "rotr  $s6,$s0,27;          xor   $t3,$t3,$s5;         xor   $s7,$s2,$s3;"
    "addu  $s4,$s4,$s6;         rotr  $t3,$t3,31;          xor   $s7,$s7,$s1;"
    "addu  $s4,$s4,$t3;         rotr  $s1,$s1,2;           addu  $s4,$s4,$s7;"
    "addu  $s3,$s3,$at;         xor   $t4,$t4,$t6;         xor   $s5,$a2,$t1;"
    "rotr  $s6,$s4,27;          xor   $t4,$t4,$s5;         xor   $s7,$s1,$s2;"
    "addu  $s3,$s3,$s6;         rotr  $t4,$t4,31;          xor   $s7,$s7,$s0;"
    "addu  $s3,$s3,$t4;         rotr  $s0,$s0,2;           addu  $s3,$s3,$s7;"
    "addu  $s2,$s2,$at;         xor   $t5,$t5,$t7;         xor   $s5,$a3,$t2;"
    "rotr  $s6,$s3,27;          xor   $t5,$t5,$s5;         xor   $s7,$s0,$s1;"
    "addu  $s2,$s2,$s6;         rotr  $t5,$t5,31;          xor   $s7,$s7,$s4;"
    "addu  $s2,$s2,$t5;         rotr  $s4,$s4,2;           addu  $s2,$s2,$s7;"
    "addu  $s1,$s1,$at;         xor   $t6,$t6,$t8;         xor   $s5,$v0,$t3;"
    "rotr  $s6,$s2,27;          xor   $t6,$t6,$s5;         xor   $s7,$s4,$s0;"
    "addu  $s1,$s1,$s6;         rotr  $t6,$t6,31;          xor   $s7,$s7,$s3;"
    "addu  $s1,$s1,$t6;         rotr  $s3,$s3,2;           addu  $s1,$s1,$s7;"
    "addu  $s0,$s0,$at;         xor   $t7,$t7,$t9;         xor   $s5,$v1,$t4;"
    "rotr  $s6,$s1,27;          xor   $t7,$t7,$s5;         xor   $s7,$s3,$s4;"
    "addu  $s0,$s0,$s6;         rotr  $t7,$t7,31;          xor   $s7,$s7,$s2;"
    "addu  $s0,$s0,$t7;         rotr  $s2,$s2,2;           addu  $s0,$s0,$s7;"

    "lui $s5,0x6ed9;"
    "ori $s5,$s5,0xeba1;"

    "bne $s5,$at,sha1_end%=;"
/*
 * T40-T59
 */
    "lui $at,0x8f1b;"
    "ori $at,$at,0xbcdc;"

    "xor   $s7,$s1,$s2;         addu  $s4,$s4,$at;         xor   $t8,$t8,$a0;"
    "xor   $s5,$t0,$t5;         rotr  $s6,$s0,27;          xor   $t8,$t8,$s5;"
    "and   $s7,$s7,$s3;         addu  $s4,$s4,$s6;         rotr  $t8,$t8,31;"
    "and   $s5,$s1,$s2;         addu  $s4,$s4,$t8;         addu  $s5,$s5,$s7;"
    "rotr  $s1,$s1,2;           addu  $s4,$s4,$s5;"
    "xor   $s7,$s0,$s1;         addu  $s3,$s3,$at;         xor   $t9,$t9,$a1;"
    "xor   $s5,$t1,$t6;         rotr  $s6,$s4,27;          xor   $t9,$t9,$s5;"
    "and   $s7,$s7,$s2;         addu  $s3,$s3,$s6;         rotr  $t9,$t9,31;"
    "and   $s5,$s0,$s1;         addu  $s3,$s3,$t9;         addu  $s5,$s5,$s7;"
    "rotr  $s0,$s0,2;           addu  $s3,$s3,$s5;"
    "xor   $s7,$s4,$s0;         addu  $s2,$s2,$at;         xor   $a0,$a0,$a2;"
    "xor   $s5,$t2,$t7;         rotr  $s6,$s3,27;          xor   $a0,$a0,$s5;"
    "and   $s7,$s7,$s1;         addu  $s2,$s2,$s6;         rotr  $a0,$a0,31;"
    "and   $s5,$s4,$s0;         addu  $s2,$s2,$a0;         addu  $s5,$s5,$s7;"
    "rotr  $s4,$s4,2;           addu  $s2,$s2,$s5;"
    "xor   $s7,$s3,$s4;         addu  $s1,$s1,$at;         xor   $a1,$a1,$a3;"
    "xor   $s5,$t3,$t8;         rotr  $s6,$s2,27;          xor   $a1,$a1,$s5;"
    "and   $s7,$s7,$s0;         addu  $s1,$s1,$s6;         rotr  $a1,$a1,31;"
    "and   $s5,$s3,$s4;         addu  $s1,$s1,$a1;         addu  $s5,$s5,$s7;"
    "rotr  $s3,$s3,2;           addu  $s1,$s1,$s5;"
    "xor   $s7,$s2,$s3;         addu  $s0,$s0,$at;         xor   $a2,$a2,$v0;"
    "xor   $s5,$t4,$t9;         rotr  $s6,$s1,27;          xor   $a2,$a2,$s5;"
    "and   $s7,$s7,$s4;         addu  $s0,$s0,$s6;         rotr  $a2,$a2,31;"
    "and   $s5,$s2,$s3;         addu  $s0,$s0,$a2;         addu  $s5,$s5,$s7;"
    "rotr  $s2,$s2,2;           addu  $s0,$s0,$s5;"

    "xor   $s7,$s1,$s2;         addu  $s4,$s4,$at;         xor   $a3,$a3,$v1;"
    "xor   $s5,$t5,$a0;         rotr  $s6,$s0,27;          xor   $a3,$a3,$s5;"
    "and   $s7,$s7,$s3;         addu  $s4,$s4,$s6;         rotr  $a3,$a3,31;"
    "and   $s5,$s1,$s2;         addu  $s4,$s4,$a3;         addu  $s5,$s5,$s7;"
    "rotr  $s1,$s1,2;           addu  $s4,$s4,$s5;"
    "xor   $s7,$s0,$s1;         addu  $s3,$s3,$at;         xor   $v0,$v0,$t0;"
    "xor   $s5,$t6,$a1;         rotr  $s6,$s4,27;          xor   $v0,$v0,$s5;"
    "and   $s7,$s7,$s2;         addu  $s3,$s3,$s6;         rotr  $v0,$v0,31;"
    "and   $s5,$s0,$s1;         addu  $s3,$s3,$v0;         addu  $s5,$s5,$s7;"
    "rotr  $s0,$s0,2;           addu  $s3,$s3,$s5;"
    "xor   $s7,$s4,$s0;         addu  $s2,$s2,$at;         xor   $v1,$v1,$t1;"
    "xor   $s5,$t7,$a2;         rotr  $s6,$s3,27;          xor   $v1,$v1,$s5;"
    "and   $s7,$s7,$s1;         addu  $s2,$s2,$s6;         rotr  $v1,$v1,31;"
    "and   $s5,$s4,$s0;         addu  $s2,$s2,$v1;         addu  $s5,$s5,$s7;"
    "rotr  $s4,$s4,2;           addu  $s2,$s2,$s5;"
    "xor   $s7,$s3,$s4;         addu  $s1,$s1,$at;         xor   $t0,$t0,$t2;"
    "xor   $s5,$t8,$a3;         rotr  $s6,$s2,27;          xor   $t0,$t0,$s5;"
    "and   $s7,$s7,$s0;         addu  $s1,$s1,$s6;         rotr  $t0,$t0,31;"
    "and   $s5,$s3,$s4;         addu  $s1,$s1,$t0;         addu  $s5,$s5,$s7;"
    "rotr  $s3,$s3,2;           addu  $s1,$s1,$s5;"
    "xor   $s7,$s2,$s3;         addu  $s0,$s0,$at;         xor   $t1,$t1,$t3;"
    "xor   $s5,$t9,$v0;         rotr  $s6,$s1,27;          xor   $t1,$t1,$s5;"
    "and   $s7,$s7,$s4;         addu  $s0,$s0,$s6;         rotr  $t1,$t1,31;"
    "and   $s5,$s2,$s3;         addu  $s0,$s0,$t1;         addu  $s5,$s5,$s7;"
    "rotr  $s2,$s2,2;           addu  $s0,$s0,$s5;"

    "xor   $s7,$s1,$s2;         addu  $s4,$s4,$at;         xor   $t2,$t2,$t4;"
    "xor   $s5,$a0,$v1;         rotr  $s6,$s0,27;          xor   $t2,$t2,$s5;"
    "and   $s7,$s7,$s3;         addu  $s4,$s4,$s6;         rotr  $t2,$t2,31;"
    "and   $s5,$s1,$s2;         addu  $s4,$s4,$t2;         addu  $s5,$s5,$s7;"
    "rotr  $s1,$s1,2;           addu  $s4,$s4,$s5;"
    "xor   $s7,$s0,$s1;         addu  $s3,$s3,$at;         xor   $t3,$t3,$t5;"
    "xor   $s5,$a1,$t0;         rotr  $s6,$s4,27;          xor   $t3,$t3,$s5;"
    "and   $s7,$s7,$s2;         addu  $s3,$s3,$s6;         rotr  $t3,$t3,31;"
    "and   $s5,$s0,$s1;         addu  $s3,$s3,$t3;         addu  $s5,$s5,$s7;"
    "rotr  $s0,$s0,2;           addu  $s3,$s3,$s5;"

    "xor   $s7,$s4,$s0;         addu  $s2,$s2,$at;         xor   $a2,$a2,$t4;"
    "xor   $s5,$t6,$t1;         xor   $t4,$t4,$a2;         rotr  $s6,$s3,27;"
    "xor   $a2,$a2,$s5;"
    "and   $s7,$s7,$s1;         addu  $s2,$s2,$s6;         rotr  $a2,$a2,31;"
    "and   $s5,$s4,$s0;         addu  $s2,$s2,$a2;         addu  $s5,$s5,$s7;"
    "rotr  $s4,$s4,2;           addu  $s2,$s2,$s5;"

    "xor   $s7,$s3,$s4;         addu  $s1,$s1,$at;         xor   $a3,$a3,$t5;"
    "xor   $s5,$t7,$t2;         xor   $t5,$t5,$a3;         rotr  $s6,$s2,27;"
    "xor   $a3,$a3,$s5;"
    "and   $s7,$s7,$s0;         addu  $s1,$s1,$s6;         rotr  $a3,$a3,31;"
    "and   $s5,$s3,$s4;         addu  $s1,$s1,$a3;         addu  $s5,$s5,$s7;"
    "rotr  $s3,$s3,2;           addu  $s1,$s1,$s5;"

    "xor   $s7,$s2,$s3;         addu  $s0,$s0,$at;         xor   $v0,$v0,$t6;"
    "xor   $s5,$t8,$t3;         xor   $t6,$t6,$v0;         rotr  $s6,$s1,27;"
    "xor   $v0,$v0,$s5;"
    "and   $s7,$s7,$s4;         addu  $s0,$s0,$s6;         rotr  $v0,$v0,31;"
    "and   $s5,$s2,$s3;         addu  $s0,$s0,$v0;         addu  $s5,$s5,$s7;"
    "rotr  $s2,$s2,2;           addu  $s0,$s0,$s5;"

    "xor   $s7,$s1,$s2;         addu  $s4,$s4,$at;         xor   $v1,$v1,$t7;"
    "xor   $s5,$t9,$a2;         xor   $t7,$t7,$v1;         rotr  $s6,$s0,27;"
    "xor   $v1,$v1,$s5;"
    "and   $s7,$s7,$s3;         addu  $s4,$s4,$s6;         rotr  $v1,$v1,31;"
    "and   $s5,$s1,$s2;         addu  $s4,$s4,$v1;         addu  $s5,$s5,$s7;"
    "rotr  $s1,$s1,2;           addu  $s4,$s4,$s5;"

    "xor   $s7,$s0,$s1;         addu  $s3,$s3,$at;         xor   $t0,$t0,$t8;"
    "xor   $s5,$a0,$a3;         xor   $t8,$t8,$t0;         rotr  $s6,$s4,27;"
    "xor   $t0,$t0,$s5;"
    "and   $s7,$s7,$s2;         addu  $s3,$s3,$s6;         rotr  $t0,$t0,31;"
    "and   $s5,$s0,$s1;         addu  $s3,$s3,$t0;         addu  $s5,$s5,$s7;"
    "rotr  $s0,$s0,2;           addu  $s3,$s3,$s5;"

    "xor   $s7,$s4,$s0;         addu  $s2,$s2,$at;         xor   $t1,$t1,$t9;"
    "xor   $s5,$a1,$v0;         xor   $t9,$t9,$t1;         rotr  $s6,$s3,27;"
    "xor   $t1,$t1,$s5;"
    "and   $s7,$s7,$s1;         addu  $s2,$s2,$s6;         rotr  $t1,$t1,31;"
    "and   $s5,$s4,$s0;         addu  $s2,$s2,$t1;         addu  $s5,$s5,$s7;"
    "rotr  $s4,$s4,2;           addu  $s2,$s2,$s5;"

    "xor   $s7,$s3,$s4;         addu  $s1,$s1,$at;         xor   $t2,$t2,$a0;"
    "xor   $s5,$t4,$v1;         xor   $a0,$a0,$t2;         rotr  $s6,$s2,27;"
    "xor   $t2,$t2,$s5;"
    "and   $s7,$s7,$s0;         addu  $s1,$s1,$s6;         rotr  $t2,$t2,31;"
    "and   $s5,$s3,$s4;         addu  $s1,$s1,$t2;         addu  $s5,$s5,$s7;"
    "rotr  $s3,$s3,2;           addu  $s1,$s1,$s5;"

    "xor   $s7,$s2,$s3;         addu  $s0,$s0,$at;         xor   $t3,$t3,$a1;"
    "xor   $s5,$t5,$t0;         xor   $a1,$a1,$t3;         rotr  $s6,$s1,27;"
    "xor   $t3,$t3,$s5;"
    "and   $s7,$s7,$s4;         addu  $s0,$s0,$s6;         rotr  $t3,$t3,31;"
    "and   $s5,$s2,$s3;         addu  $s0,$s0,$t3;         addu  $s5,$s5,$s7;"
    "rotr  $s2,$s2,2;           addu  $s0,$s0,$s5;"
/*
 * T60-T79 is the same as T20-T39 with other input constants. Registers
 * have been exchanged in T52-T59. This saves a footprint of about 1K for only
 * 8 extra instructions
 */
    "lui $at,0xca62;"
    "ori $at,$at,0xc1d6;"

    "beq $t0,$t0,sha1_redo%=;"
    "sha1_end%=:;"

    "lw $s7,%0;"
    "lw $t0,0($s7);"
    "lw $t1,4($s7);"
    "lw $t2,8($s7);"
    "lw $t3,12($s7);"
    "lw $t4,16($s7);"

    "addu $s0,$s0,$t0;"
    "addu $s1,$s1,$t1;"
    "addu $s2,$s2,$t2;"
    "addu $s3,$s3,$t3;"
    "addu $s4,$s4,$t4;"

    "sw $s0,0($s7);"
    "sw $s1,4($s7);"
    "sw $s2,8($s7);"
    "sw $s3,12($s7);"
    "sw $s4,16($s7);"

    :
    : "m"(digest),
      "m"(data)
    : "a0","a1","a2","a3","at",
      "t0","t1","t2","t3","t4","t5","t6","t7","t8","t9",
      "v0","v1",
      "s0","s1","s2","s3","s4","s5","s6","s7" );

#ifdef DEBUG
/*
 * increase caluclation counter
 */
  mi_sha1_bytes_calculated += 64;
#endif
}

/*
 * mi_sha1_init() initializes SHA1 value
 */
static int mi_sha1_init(struct shash_desc *desc)
{
  struct mi_sha1_ctx *sctx = shash_desc_ctx(desc);

  sctx->state[0] = 0x67452301;
  sctx->state[1] = 0xefcdab89;
  sctx->state[2] = 0x98badcfe;
  sctx->state[3] = 0x10325476;
  sctx->state[4] = 0xc3d2e1f0;
  sctx->count    = 0;

  return 0;
}

/*
 * mi_sha1_update() calculate SHA1 value over input segment
 */
static int mi_sha1_update(struct shash_desc *desc, const u8 *data,
                        unsigned int len)
{
  struct mi_sha1_ctx *sctx = shash_desc_ctx(desc);
  unsigned int partial, done;
  const u8 *src;

  partial = sctx->count & 0x3f;
  sctx->count += len;
  done = 0;
  src = data;

  if ((partial + len) > 63) {
    if (partial) {
      done = -partial;
      memcpy(sctx->buffer + partial, data, done + 64);
      src = sctx->buffer;
    }

    do {
      mi_sha1_transform(sctx->state, src);
      done += 64;
      src = data + done;
    } while (done + 63 < len);

    partial = 0;
  }

  if (len - done > 0) {
    memcpy(sctx->buffer + partial, src, len - done);
  }

  return 0;
}

/*
 * finalize SHA1 values with last bits of input data
 */
static int mi_sha1_final(struct shash_desc *desc, u8 *out)
{
  struct mi_sha1_ctx *sctx = shash_desc_ctx(desc);
  __be32 *dst = (__be32 *)out;
  u32 i, index, padlen;
  __be64 bits;
  static const u8 padding[64] = { 0x80, };

  bits = cpu_to_be64(sctx->count << 3);

  /* Pad out to 56 mod 64 */
  index = sctx->count & 0x3f;
  padlen = (index < 56) ? (56 - index) : ((64+56) - index);
  mi_sha1_update(desc, padding, padlen);

  /* Append length */
  mi_sha1_update(desc, (const u8 *)&bits, sizeof(bits));

  /* Store state in digest */
  for (i = 0; i < 5; i++)
    dst[i] = cpu_to_be32(sctx->state[i]);

  /* Wipe context */
  memset(sctx, 0, sizeof *sctx);

  return 0;
}

/*
 * copy SHA1 context data to userspace
 */
static int mi_sha1_export(struct shash_desc *desc, void *out)
{
  struct mi_sha1_ctx *sctx = shash_desc_ctx(desc);

  memcpy(out, sctx, sizeof(*sctx));
  return 0;
}

/*
 * import SHA1 context from userspace
 */
static int mi_sha1_import(struct shash_desc *desc, const void *in)
{
  struct mi_sha1_ctx *sctx = shash_desc_ctx(desc);

  memcpy(sctx, in, sizeof(*sctx));
  return 0;
}

/*
 * algorithm registration
 */
static struct shash_alg mi_sha1_alg = {
  .digestsize       = SHA1_DIGEST_SIZE,
  .init             = mi_sha1_init,
  .update           = mi_sha1_update,
  .final            = mi_sha1_final,
  .export           = mi_sha1_export,
  .import           = mi_sha1_import,
  .descsize         = sizeof(struct mi_sha1_ctx),
  .statesize        = sizeof(struct mi_sha1_ctx),
  .base             = {
    .cra_name         = "sha1",
    .cra_priority     = 200,
    .cra_driver_name  = "sha1-mcespi",
    .cra_flags        = CRYPTO_ALG_TYPE_SHASH,
    .cra_blocksize    = SHA1_BLOCK_SIZE,
    .cra_module       = THIS_MODULE,
  }
};

/*
 * ---------------------------------------------------------------------------
 * MD5 Message Digest Algorithm (RFC1321)
 * ---------------------------------------------------------------------------
 */

u32 mi_md5_tab[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

#define MD5_DIGEST_SIZE         16
#define MD5_BLOCK_SIZE          64
#define MD5_BLOCK_WORDS         16
#define MD5_HASH_WORDS          4

struct mi_md5_ctx {
  u32 hash[MD5_HASH_WORDS];
  u32 block[MD5_BLOCK_WORDS];
  u64 byte_count;
};

/*
 * helper for byte swap
 */
static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
  while (words--) {
    __cpu_to_le32s(buf);
    buf++;
  }
}

/*
 * mi_md5_transform() calulates 128 bit (16 bytes) MD5 value
 * from 512 bit (64 byte) input data
 */
void static mi_md5_transform(u32 *hash, u32 const *in)
{
  u32 *md5tab = mi_md5_tab;

  __asm__ volatile (
   ".set noat;"
   ".set noreorder;"
/*
 * load MD5 value
 */
    "lw $s7,%0;"
    "lw $s0,0($s7);"
    "lw $s1,4($s7);"
    "lw $s2,8($s7);"
    "lw $s3,12($s7);"
/*
 * load input data
 */
    "lw    $s7,%1;"
    "lwl   $t0,0($s7);          lwl   $t1,4($s7);"
    "lwl   $t2,8($s7);          lwl   $t3,12($s7);"
    "lwl   $t4,16($s7);         lwl   $t5,20($s7);"
    "lwl   $t6,24($s7);         lwl   $t7,28($s7);"
    "lwl   $t8,32($s7);         lwl   $t9,36($s7);"
    "lwl   $a0,40($s7);         lwl   $a1,44($s7);"
    "lwl   $a2,48($s7);         lwl   $a3,52($s7);"
    "lwl   $v0,56($s7);         lwl   $v1,60($s7);"

    "lwr   $t0,3($s7);          lwr   $t1,7($s7);"
    "lwr   $t2,11($s7);         lwr   $t3,15($s7);"
    "lwr   $t4,19($s7);         lwr   $t5,23($s7);"
    "lwr   $t6,27($s7);         lwr   $t7,31($s7);"
    "lwr   $t8,35($s7);         lwr   $t9,39($s7);"
    "lwr   $a0,43($s7);         lwr   $a1,47($s7);"
    "lwr   $a2,51($s7);         lwr   $a3,55($s7);"
    "lwr   $v0,59($s7);         lwr   $v1,63($s7);"
/*
 * MD5 is little endian (lowest byte first) so we have to swap the bytes
 */
    "wsbh  $t0,$t0;             wsbh  $t1,$t1;"
    "wsbh  $t2,$t2;             wsbh  $t3,$t3;"
    "wsbh  $t4,$t4;             wsbh  $t5,$t5;"
    "wsbh  $t6,$t6;             wsbh  $t7,$t7;"
    "wsbh  $t8,$t8;             wsbh  $t9,$t9;"
    "wsbh  $a0,$a0;             wsbh  $a1,$a1;"
    "wsbh  $a2,$a2;             wsbh  $a3,$a3;"
    "wsbh  $v0,$v0;             wsbh  $v1,$v1;"


    "rotr  $t0,$t0,16;          rotr  $t1,$t1,16;"
    "rotr  $t2,$t2,16;          rotr  $t3,$t3,16;"
    "rotr  $t4,$t4,16;          rotr  $t5,$t5,16;"
    "rotr  $t6,$t6,16;          rotr  $t7,$t7,16;"
    "rotr  $t8,$t8,16;          rotr  $t9,$t9,16;"
    "rotr  $a0,$a0,16;          rotr  $a1,$a1,16;"
    "rotr  $a2,$a2,16;          rotr  $a3,$a3,16;"
    "rotr  $v0,$v0,16;          rotr  $v1,$v1,16;"

    "lw $at,%2;"

// T00-T15

    "xor   $s4,$s2,$s3;         lw    $s5,0($at);          and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s3;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t0;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,25;          addu  $s0,$s0,$s1;"

    "xor   $s4,$s1,$s2;         lw    $s5,4($at);          and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s2;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$t1;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,20;          addu  $s3,$s3,$s0;"

    "xor   $s4,$s0,$s1;         lw    $s5,8($at);          and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s1;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$t2;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,15;          addu  $s2,$s2,$s3;"

    "xor   $s4,$s3,$s0;         lw    $s5,12($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s0;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$t3;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,10;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s2,$s3;         lw    $s5,16($at);         and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s3;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t4;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,25;          addu  $s0,$s0,$s1;"

    "xor   $s4,$s1,$s2;         lw    $s5,20($at);         and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s2;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$t5;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,20;          addu  $s3,$s3,$s0;"

    "xor   $s4,$s0,$s1;         lw    $s5,24($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s1;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$t6;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,15;          addu  $s2,$s2,$s3;"

    "xor   $s4,$s3,$s0;         lw    $s5,28($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s0;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$t7;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,10;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s2,$s3;         lw    $s5,32($at);         and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s3;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t8;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,25;          addu  $s0,$s0,$s1;"

    "xor   $s4,$s1,$s2;         lw    $s5,36($at);         and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s2;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$t9;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,20;          addu  $s3,$s3,$s0;"

    "xor   $s4,$s0,$s1;         lw    $s5,40($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s1;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$a0;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,15;          addu  $s2,$s2,$s3;"

    "xor   $s4,$s3,$s0;         lw    $s5,44($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s0;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$a1;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,10;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s2,$s3;         lw    $s5,48($at);         and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s3;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$a2;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,25;          addu  $s0,$s0,$s1;"

    "xor   $s4,$s1,$s2;         lw    $s5,52($at);         and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s2;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$a3;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,20;          addu  $s3,$s3,$s0;"

    "xor   $s4,$s0,$s1;         lw    $s5,56($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s1;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$v0;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,15;          addu  $s2,$s2,$s3;"

    "xor   $s4,$s3,$s0;         lw    $s5,60($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s0;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$v1;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,10;          addu  $s1,$s1,$s2;"

// T16-T31

    "xor   $s4,$s1,$s2;         lw    $s5,64($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s2;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t1;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,27;          addu  $s0,$s0,$s1;"
    "xor   $s4,$s0,$s1;         lw    $s5,68($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s1;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$t6;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,23;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s5,72($at);         and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s0;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$a1;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,18;          addu  $s2,$s2,$s3;"
    "xor   $s4,$s2,$s3;         lw    $s5,76($at);         and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s3;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$t0;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,12;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s5,80($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s2;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t5;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,27;          addu  $s0,$s0,$s1;"
    "xor   $s4,$s0,$s1;         lw    $s5,84($at);         and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s1;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$a0;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,23;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s5,88($at);         and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s0;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$v1;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,18;          addu  $s2,$s2,$s3;"
    "xor   $s4,$s2,$s3;         lw    $s5,92($at);         and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s3;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$t4;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,12;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s5,96($at);         and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s2;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$t9;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,27;          addu  $s0,$s0,$s1;"
    "xor   $s4,$s0,$s1;         lw    $s5,100($at);        and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s1;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$v0;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,23;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s5,104($at);        and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s0;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$t3;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,18;          addu  $s2,$s2,$s3;"
    "xor   $s4,$s2,$s3;         lw    $s5,108($at);        and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s3;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$t8;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,12;          addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s5,112($at);        and   $s4,$s4,$s3;"
    "xor   $s4,$s4,$s2;         addu  $s0,$s0,$s5;         addu  $s4,$s4,$a3;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,27;          addu  $s0,$s0,$s1;"
    "xor   $s4,$s0,$s1;         lw    $s5,116($at);        and   $s4,$s4,$s2;"
    "xor   $s4,$s4,$s1;         addu  $s3,$s3,$s5;         addu  $s4,$s4,$t2;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,23;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s5,120($at);        and   $s4,$s4,$s1;"
    "xor   $s4,$s4,$s0;         addu  $s2,$s2,$s5;         addu  $s4,$s4,$t7;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,18;          addu  $s2,$s2,$s3;"
    "xor   $s4,$s2,$s3;         lw    $s5,124($at);        and   $s4,$s4,$s0;"
    "xor   $s4,$s4,$s3;         addu  $s1,$s1,$s5;         addu  $s4,$s4,$a2;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,12;          addu  $s1,$s1,$s2;"

// T32-T47

    "xor   $s4,$s1,$s2;         lw    $s7,128($at);        xor   $s5,$s4,$s3;"
    "addu  $s0,$s0,$s7;         addu  $s0,$s0,$t5;         addu  $s0,$s0,$s5;"
    "rotr  $s0,$s0,28;          addu  $s0,$s0,$s1;         xor   $s4,$s4,$s0;"
    "lw    $s7,132($at);        addu  $s3,$s3,$s7;         addu  $s3,$s3,$t8;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,21;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s7,136($at);        xor   $s5,$s4,$s1;"
    "addu  $s2,$s2,$s7;         addu  $s2,$s2,$a1;         addu  $s2,$s2,$s5;"
    "rotr  $s2,$s2,16;          addu  $s2,$s2,$s3;         xor   $s4,$s4,$s2;"
    "lw    $s7,140($at);        addu  $s1,$s1,$s7;         addu  $s1,$s1,$v0;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,9;           addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s7,144($at);        xor   $s5,$s4,$s3;"
    "addu  $s0,$s0,$s7;         addu  $s0,$s0,$t1;         addu  $s0,$s0,$s5;"
    "rotr  $s0,$s0,28;          addu  $s0,$s0,$s1;         xor   $s4,$s4,$s0;"
    "lw    $s7,148($at);        addu  $s3,$s3,$s7;         addu  $s3,$s3,$t4;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,21;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s7,152($at);        xor   $s5,$s4,$s1;"
    "addu  $s2,$s2,$s7;         addu  $s2,$s2,$t7;         addu  $s2,$s2,$s5;"
    "rotr  $s2,$s2,16;          addu  $s2,$s2,$s3;         xor   $s4,$s4,$s2;"
    "lw    $s7,156($at);        addu  $s1,$s1,$s7;         addu  $s1,$s1,$a0;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,9;           addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s7,160($at);        xor   $s5,$s4,$s3;"
    "addu  $s0,$s0,$s7;         addu  $s0,$s0,$a3;         addu  $s0,$s0,$s5;"
    "rotr  $s0,$s0,28;          addu  $s0,$s0,$s1;         xor   $s4,$s4,$s0;"
    "lw    $s7,164($at);        addu  $s3,$s3,$s7;         addu  $s3,$s3,$t0;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,21;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s7,168($at);        xor   $s5,$s4,$s1;"
    "addu  $s2,$s2,$s7;         addu  $s2,$s2,$t3;         addu  $s2,$s2,$s5;"
    "rotr  $s2,$s2,16;          addu  $s2,$s2,$s3;         xor   $s4,$s4,$s2;"
    "lw    $s7,172($at);        addu  $s1,$s1,$s7;         addu  $s1,$s1,$t6;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,9;           addu  $s1,$s1,$s2;"

    "xor   $s4,$s1,$s2;         lw    $s7,176($at);        xor   $s5,$s4,$s3;"
    "addu  $s0,$s0,$s7;         addu  $s0,$s0,$t9;         addu  $s0,$s0,$s5;"
    "rotr  $s0,$s0,28;          addu  $s0,$s0,$s1;         xor   $s4,$s4,$s0;"
    "lw    $s7,180($at);        addu  $s3,$s3,$s7;         addu  $s3,$s3,$a2;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,21;          addu  $s3,$s3,$s0;"
    "xor   $s4,$s3,$s0;         lw    $s7,184($at);        xor   $s5,$s4,$s1;"
    "addu  $s2,$s2,$s7;         addu  $s2,$s2,$v1;         addu  $s2,$s2,$s5;"
    "rotr  $s2,$s2,16;          addu  $s2,$s2,$s3;         xor   $s4,$s4,$s2;"
    "lw    $s7,188($at);        addu  $s1,$s1,$s7;         addu  $s1,$s1,$t2;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,9;           addu  $s1,$s1,$s2;"

// T48-T63

    "nor   $s4,$s3,$s3;         lw    $s7,192($at);        or    $s4,$s4,$s1;"
    "addu  $s0,$s0,$s7;         xor   $s4,$s4,$s2;         addu  $s0,$s0,$t0;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,26;          addu  $s0,$s0,$s1;"
    "nor   $s4,$s2,$s2;         lw    $s7,196($at);        or    $s4,$s4,$s0;"
    "addu  $s3,$s3,$s7;         xor   $s4,$s4,$s1;         addu  $s3,$s3,$t7;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,22;          addu  $s3,$s3,$s0;"
    "nor   $s4,$s1,$s1;         lw    $s7,200($at);        or    $s4,$s4,$s3;"
    "addu  $s2,$s2,$s7;         xor   $s4,$s4,$s0;         addu  $s2,$s2,$v0;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,17;          addu  $s2,$s2,$s3;"
    "nor   $s4,$s0,$s0;         lw    $s7,204($at);        or    $s4,$s4,$s2;"
    "addu  $s1,$s1,$s7;         xor   $s4,$s4,$s3;         addu  $s1,$s1,$t5;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,11;          addu  $s1,$s1,$s2;"

    "nor   $s4,$s3,$s3;         lw    $s7,208($at);        or    $s4,$s4,$s1;"
    "addu  $s0,$s0,$s7;         xor   $s4,$s4,$s2;         addu  $s0,$s0,$a2;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,26;          addu  $s0,$s0,$s1;"
    "nor   $s4,$s2,$s2;         lw    $s7,212($at);        or    $s4,$s4,$s0;"
    "addu  $s3,$s3,$s7;         xor   $s4,$s4,$s1;         addu  $s3,$s3,$t3;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,22;          addu  $s3,$s3,$s0;"
    "nor   $s4,$s1,$s1;         lw    $s7,216($at);        or    $s4,$s4,$s3;"
    "addu  $s2,$s2,$s7;         xor   $s4,$s4,$s0;         addu  $s2,$s2,$a0;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,17;          addu  $s2,$s2,$s3;"
    "nor   $s4,$s0,$s0;         lw    $s7,220($at);        or    $s4,$s4,$s2;"
    "addu  $s1,$s1,$s7;         xor   $s4,$s4,$s3;         addu  $s1,$s1,$t1;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,11;          addu  $s1,$s1,$s2;"

    "nor   $s4,$s3,$s3;         lw    $s7,224($at);        or    $s4,$s4,$s1;"
    "addu  $s0,$s0,$s7;         xor   $s4,$s4,$s2;         addu  $s0,$s0,$t8;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,26;          addu  $s0,$s0,$s1;"
    "nor   $s4,$s2,$s2;         lw    $s7,228($at);        or    $s4,$s4,$s0;"
    "addu  $s3,$s3,$s7;         xor   $s4,$s4,$s1;         addu  $s3,$s3,$v1;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,22;          addu  $s3,$s3,$s0;"
    "nor   $s4,$s1,$s1;         lw    $s7,232($at);        or    $s4,$s4,$s3;"
    "addu  $s2,$s2,$s7;         xor   $s4,$s4,$s0;         addu  $s2,$s2,$t6;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,17;          addu  $s2,$s2,$s3;"
    "nor   $s4,$s0,$s0;         lw    $s7,236($at);        or    $s4,$s4,$s2;"
    "addu  $s1,$s1,$s7;         xor   $s4,$s4,$s3;         addu  $s1,$s1,$a3;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,11;          addu  $s1,$s1,$s2;"

    "nor   $s4,$s3,$s3;         lw    $s7,240($at);        or    $s4,$s4,$s1;"
    "addu  $s0,$s0,$s7;         xor   $s4,$s4,$s2;         addu  $s0,$s0,$t4;"
    "addu  $s0,$s0,$s4;         rotr  $s0,$s0,26;          addu  $s0,$s0,$s1;"
    "nor   $s4,$s2,$s2;         lw    $s7,244($at);        or    $s4,$s4,$s0;"
    "addu  $s3,$s3,$s7;         xor   $s4,$s4,$s1;         addu  $s3,$s3,$a1;"
    "addu  $s3,$s3,$s4;         rotr  $s3,$s3,22;          addu  $s3,$s3,$s0;"
    "nor   $s4,$s1,$s1;         lw    $s7,248($at);        or    $s4,$s4,$s3;"
    "addu  $s2,$s2,$s7;         xor   $s4,$s4,$s0;         addu  $s2,$s2,$t2;"
    "addu  $s2,$s2,$s4;         rotr  $s2,$s2,17;          addu  $s2,$s2,$s3;"
    "nor   $s4,$s0,$s0;         lw    $s7,252($at);        or    $s4,$s4,$s2;"
    "addu  $s1,$s1,$s7;         xor   $s4,$s4,$s3;         addu  $s1,$s1,$t9;"
    "addu  $s1,$s1,$s4;         rotr  $s1,$s1,11;          addu  $s1,$s1,$s2;"

/*
 * load old MD5 value
 */
    "lw $s7,%0;"
    "lw $t0,0($s7);"
    "lw $t1,4($s7);"
    "lw $t2,8($s7);"
    "lw $t3,12($s7);"
/*
 * add values of this calculation
 */
    "addu $s0,$s0,$t0;"
    "addu $s1,$s1,$t1;"
    "addu $s2,$s2,$t2;"
    "addu $s3,$s3,$t3;"
/*
 * Store MD5 value
 */
    "sw $s0,0($s7);"
    "sw $s1,4($s7);"
    "sw $s2,8($s7);"
    "sw $s3,12($s7);"

    :
    : "m"(hash),
      "m"(in),
      "m"(md5tab)
    : "a0","a1","a2","a3","at",
      "t0","t1","t2","t3","t4","t5","t6","t7","t8","t9",
      "v0","v1",
      "s0","s1","s2","s3","s4","s5","s6","s7" );

#ifdef DEBUG
  mi_md5_bytes_calculated += 64;
#endif

}

/*
 * initialize MD5 algorithm start values
 */
static int mi_md5_init(struct shash_desc *desc)
{
  struct mi_md5_ctx *mctx = shash_desc_ctx(desc);

  mctx->hash[0] = 0x67452301;
  mctx->hash[1] = 0xefcdab89;
  mctx->hash[2] = 0x98badcfe;
  mctx->hash[3] = 0x10325476;
  mctx->byte_count = 0;

  return 0;
}

/*
 * caluclate MD5 for one segment
 */
static int mi_md5_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
  struct mi_md5_ctx *mctx = shash_desc_ctx(desc);
  const u32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);

  mctx->byte_count += len;

  // input data cannot fill up buffer for a transformation - store it - end

  if (avail > len) {
    memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
      data, len);
    return 0;
  }

  // if input buffer is not empty fill it up - transform buffer afterwards

  if (avail!=sizeof(mctx->block)) {
    memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
      data, avail);

    mi_md5_transform(mctx->hash, mctx->block);
    data += avail;
    len -= avail;
  }

  // transform input data directly

  while (len >= sizeof(mctx->block)) {
    mi_md5_transform(mctx->hash,(u32 *)data);
    data += sizeof(mctx->block);
    len -= sizeof(mctx->block);
  }

  // store rest of input data in buffer

  memcpy(mctx->block, data, len);

  return 0;
}

/*
 * finalize caluclation with rest of data
 */
static int mi_md5_final(struct shash_desc *desc, u8 *out)
{
  struct mi_md5_ctx *mctx = shash_desc_ctx(desc);
  const unsigned int offset = mctx->byte_count & 0x3f;
  char *p = (char *)mctx->block + offset;
  int padding = 56 - (offset + 1);

  *p++ = 0x80;
  if (padding < 0) {
    memset(p, 0x00, padding + sizeof (u64));
    mi_md5_transform(mctx->hash, mctx->block);
    p = (char *)mctx->block;
    padding = 56;
  }

  memset(p, 0, padding);

  mctx->block[14] = le32_to_cpu(mctx->byte_count << 3);
  mctx->block[15] = le32_to_cpu(mctx->byte_count >> 29);
  mi_md5_transform(mctx->hash, mctx->block);

  cpu_to_le32_array(mctx->hash, sizeof(mctx->hash) / sizeof(u32));
  memcpy(out, mctx->hash, sizeof(mctx->hash));
  memset(mctx, 0, sizeof(*mctx));

  return 0;
}

/*
 * export MD5 context to userspace
 */
static int mi_md5_export(struct shash_desc *desc, void *out)
{
  struct mi_md5_ctx *ctx = shash_desc_ctx(desc);

  memcpy(out, ctx, sizeof(*ctx));
  return 0;
}

/*
 * import MD5 context from userspace
 */
static int mi_md5_import(struct shash_desc *desc, const void *in)
{
  struct mi_md5_ctx *ctx = shash_desc_ctx(desc);

  memcpy(ctx, in, sizeof(*ctx));
  return 0;
}

/*
 * algorithm registration
 */
static struct shash_alg mi_md5_alg = {
  .digestsize       = MD5_DIGEST_SIZE,
  .init             = mi_md5_init,
  .update           = mi_md5_update,
  .final            = mi_md5_final,
  .export           = mi_md5_export,
  .import           = mi_md5_import,
  .descsize         = sizeof(struct mi_md5_ctx),
  .statesize        = sizeof(struct mi_md5_ctx),
  .base             = {
    .cra_name         = "md5",
    .cra_priority     = 200,
    .cra_driver_name  = "md5-mcespi",
    .cra_flags        = CRYPTO_ALG_TYPE_SHASH,
    .cra_blocksize    = MD5_BLOCK_SIZE,
    .cra_module       = THIS_MODULE,
  }
};

/*
 * ---------------------------------------------------------------------------
 * initialization part
 * ---------------------------------------------------------------------------
 */

static int __init mi_init(void)
{
  int err,i;

  if (*((u8 *)mi_aes_enctab) != 0xa5) {
    printk(KERN_ERR "mcespi only for big endian (at the moment)\n");
    return -EPERM;
  }

#ifdef DEBUG
  mi_debug();
#endif

  mi_aes_encdec=mi_aes_encdectab;
  mi_aes_encdec=PTR_ALIGN(mi_aes_encdec,1024);

  for (i=0;i<256;i++) {
    *(mi_aes_encdec+i)      = le32_to_cpu(mi_aes_enctab[i]);
    *(mi_aes_encdec+i+256)  = le32_to_cpu(mi_aes_enctab[i]<<8  | mi_aes_enctab[i]>>24);
    *(mi_aes_encdec+i+512)  = le32_to_cpu(mi_aes_enctab[i]<<16 | mi_aes_enctab[i]>>16);
    *(mi_aes_encdec+i+768)  = le32_to_cpu(mi_aes_enctab[i]<<24 | mi_aes_enctab[i]>>8);

    *(mi_aes_encdec+i+1024) = le32_to_cpu(mi_aes_dectab[i]);
    *(mi_aes_encdec+i+1280) = le32_to_cpu(mi_aes_dectab[i]<<8  | mi_aes_dectab[i]>>24);
    *(mi_aes_encdec+i+1536) = le32_to_cpu(mi_aes_dectab[i]<<16 | mi_aes_dectab[i]>>16);
    *(mi_aes_encdec+i+1792) = le32_to_cpu(mi_aes_dectab[i]<<24 | mi_aes_dectab[i]>>8);
  }
  for (i=0;i<64;i++) {
    *(mi_aes_encdec+2048+i) = mi_aes_dectab[i+256];
  }

  err=crypto_register_alg(&mi_aes_alg);
  if (err) goto error_aes;
  err=crypto_register_shash(&mi_sha1_alg);
  if (err) goto error_sha1;
  err=crypto_register_shash(&mi_md5_alg);
  if (err) goto error_md5;
  err=crypto_register_alg(&mi_cbc_alg);
  if (err) goto error_cbc;

  return err;

error_cbc:
  crypto_unregister_shash(&mi_md5_alg);
error_md5:
  crypto_unregister_shash(&mi_sha1_alg);
error_sha1:
  crypto_unregister_alg(&mi_aes_alg);
error_aes:

  return err;
}

static void __exit mi_exit(void)
{
  crypto_unregister_alg  (&mi_aes_alg);
  crypto_unregister_shash(&mi_sha1_alg);
  crypto_unregister_shash(&mi_md5_alg);
  crypto_unregister_alg  (&mi_cbc_alg);
}

module_init(mi_init);
module_exit(mi_exit);

MODULE_DESCRIPTION("IPsec algorithms");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("mcespi");
