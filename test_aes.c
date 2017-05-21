#include "test_aes.h"

u8 TEST_IN[AES_BLOCK_LEN] = {
	0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb,
	0xcc, 0xdd, 0xee, 0xff,
};

u8 TEST_KEY[AES_KEYWIDTH_256 / BITS_PER_BYTE] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f,
};

u8 *TEST_OUT[1024] = {
};

u32 gt_aes_mode[] = {
	AES_MODE_ECB,
	AES_MODE_CBC,
};

u32 gt_aes_padding[] = {
	AES_PADDING_00,
	AES_PADDING_80,
};

u32 gt_aes_direction[] = {
	AES_DIR_ENCRYPT,
	AES_DIR_DECRYPT,
};

u32 gt_aes_keywidth[] = {
	AES_KEYWIDTH_128,
	AES_KEYWIDTH_192,
	AES_KEYWIDTH_256,
};

u8 TEST_AES128_ECB_PAD00_E_IN16_O[] = {
	0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 
	0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};
u8 *gt_aes_out[] = {
	TEST_AES128_ECB_PAD00_E_IN16_O,

};

u32 gt_aes_dinlen[] = {
	16, 15, 16, 17, 32, 64, 65,
};

u32 test_aes_cipher_item(idx)
{
	u32 ret = ERROR;

	aes_param aesparam;
	idx = 0;

	aesparam.mode = gt_aes_mode[idx];
	aesparam.padding = gt_aes_padding[idx];
	aesparam.direction = gt_aes_direction[idx];
	aesparam.keywidth = gt_aes_keywidth[idx];
	aesparam.pkey = TEST_KEY;
	aesparam.pdin = TEST_IN;
	aesparam.pdinlen = gt_aes_dinlen + idx;
	aesparam.pdout = (u8 *)TEST_OUT;
	*aesparam.pdoutlen = round_up(*aesparam.pdinlen, AES_BLOCK_LEN);

	printf("aesparam.mode      = %d\n", aesparam.mode);
	printf("aesparam.padding   = %d\n", aesparam.padding);
	printf("aesparam.direction = %d\n", aesparam.direction);
	printf("aesparam.keywidth  = %d\n", aesparam.keywidth);
	printf("*aesparam.pdinlen  = %d\n", *aesparam.pdinlen);
	printf("aesparam.pdoutlen  = %d\n", *aesparam.pdoutlen);
	printf("aesparam.pkey:\n");
	dump_mem(aesparam.pkey, aesparam.keywidth / BITS_PER_BYTE);
	printf("aesparam.pdin:\n");
	dump_mem(aesparam.pdin, *aesparam.pdinlen);

	ret = aes_cipher(&aesparam);
	printf("aesparam.pdout:\n");
	dump_mem(aesparam.pdout, *aesparam.pdoutlen);

	if (0 != memcmp(TEST_OUT, gt_aes_out[idx], *aesparam.pdoutlen)) {
		printf("outdata should be\n");
		dump_mem(gt_aes_out[idx], *aesparam.pdoutlen);
		printf("real data are\n");
		dump_mem(TEST_OUT, *aesparam.pdoutlen);
	}
}

