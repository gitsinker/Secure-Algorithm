#include "aes.h"
#include <stdio.h>

u8 TEST_IN[AES_BLOCK_LEN] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};
u8 TEST_KEY[AES_KEYWIDTH_256] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
};
u8 TEST_OUT[AES_BLOCK_LEN] = {
};

u32 get_endian(void) {
	u32 value = 0x12345678;
	
	if (0x78 == *(u8 *)(&value)) {
		printf("little endian!\n");
		return 0;
	} else {
		printf("big endian!\n");
		return 1;
	}
};
int main(void) {
	u32 ret = ERROR;

	get_endian();

	ret = aes_enc_block(TEST_IN, TEST_KEY, AES_KEYWIDTH_128, TEST_OUT);

	return ret;
}

u32 aes_enc_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout) {
	u32 ret = ERROR;

	u32 value = 0x12345678;
	printf("value=0x%x\n", value);
	u8 *p = (u8 *)(&value);
	printf("addr:0x%x, value:0x%x\n", (u32)p, (u32)(*p));
	p++;
	printf("addr:0x%x, value:0x%x\n", (u32)p, (u32)(*p));
	p++;
	printf("addr:0x%x, value:0x%x\n", (u32)p, (u32)(*p));
	p++;
	printf("addr:0x%x, value:0x%x\n", (u32)p, (u32)(*p));

	ret = OK;

	return ret;
}
