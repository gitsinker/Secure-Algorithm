#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

u32 Nk;     /* number of 32-bit word of key   */
u32 Nr;     /* number of round                */
u32 Nb = 4; /* number of 32-bit word of state */
u8 R[] = { 0x02, 0, 0, 0 };

u32 round_up(u32 value, u32 modulus)
{
	if (!modulus) {
		return value;
	} else {
		return ((value + modulus - 1) / modulus * modulus);
	}
}

u32 memcpy(u8 *dst, u8 *src, u32 len)
{
	if (NULL == dst || NULL == src) {
		return ERROR;
	}
	while (len--) {
		*dst = *src;
		dst++;
		src++;
	}

	return OK;
}

u32 memcmp(u8 *dst, u8 *src, u32 len)
{
	if (NULL == dst || NULL == src) {
		return ERROR;
	}

	while (len--) {
		if (*dst != *src) {
			return ERROR;
		}
		dst++;
		src++;
	}

	return OK;
}

void dump_mem(u8 *pmem, u32 memlen)
{
	u8 i;
	u8 *p = pmem;
	for (i = 0; i < memlen; i++) {
		if (0 == i % 8) {
			printf("\n");
		}
		printf("0x%x, ", *p);
		p++;
	}
	printf("\n");
}
static u8 s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, // f
};

static u8 inv_s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, // f
};

u32 get_endian(void)
{
	u32 value = 0x12345678;

	if (0x78 == *(u8 *)(&value)) {
		printf("little endian!\n");
		return 0;
	} else {
		printf("big endian!\n");
		return 1;
	}
};

/*******************************************************************************
func:
             add_round_key
description:
             add round key to the state using and XOR operation
             length of round key equals to size of state
param:
             state pointer to state
             w     pointer to key
*******************************************************************************/
void add_round_key(u8 *state, u8 *w, u32 r)
{
	u8 j;

	for (j = 0; j < 4; j++) {
		state[4 * 0 + j] ^= w[4 * 4 * r + 4 * j + 0];
		state[4 * 1 + j] ^= w[4 * 4 * r + 4 * j + 1];
		state[4 * 2 + j] ^= w[4 * 4 * r + 4 * j + 2];
		state[4 * 3 + j] ^= w[4 * 4 * r + 4 * j + 3];
	}
}

/*******************************************************************************
func:
             sub_bytes
description:
             sub each byte of the state by S-box
param:
             state pointer to state
*******************************************************************************/
void sub_bytes(u8 *state)
{
	u8 i, j;
	u8 row, col;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			row = (state[4 * i + j] & 0xf0) >> 4;
			col = state[4 * i + j] & 0x0f;
			state[4 * i + j] = s_box[16 * row + col];
		}
	}
}

/*******************************************************************************
func:
             inv_sub_bytes
description:
             sub each byte of the state by inv_S-box
param:
             state pointer to state
*******************************************************************************/
void inv_sub_bytes(u8 *state)
{
	u8 i, j;
	u8 row, col;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			row = (state[4 * i + j] & 0xf0) >> 4;
			col = (state[4 * i + j] & 0x0f);
			state[4 * i + j] = inv_s_box[16 * row + col];
		}
	}
}

/*******************************************************************************
func:
             shift_rows
description:
             left shift last three rows by different offsets
param:
             state pointer to state
*******************************************************************************/
void shift_rows(u8 *state)
{
	u8 i, k;
	u8 tmp;
	for (i = 1; i < 4; i ++) {
		k = i;
		while (k--) {
			tmp = state[4 * i + 0];
			state[4 * i + 0] = state[4 * i + 1];
			state[4 * i + 1] = state[4 * i + 2];
			state[4 * i + 2] = state[4 * i + 3];
			state[4 * i + 3] = tmp;
		}
	}
}

/*******************************************************************************
func:
             inv_shift_rows
description:
             right shift last three rows by different offsets
param:
             state pointer to state
*******************************************************************************/
void inv_shift_rows(u8 *state)
{
	u8 i, k;
	u8 tmp;
	for (i = 1; i < 4; i ++) {
		k = i;
		while (k--) {
			tmp = state[4 * i + 3];
			state[4 * i + 3] = state[4 * i + 2];
			state[4 * i + 2] = state[4 * i + 1];
			state[4 * i + 1] = state[4 * i + 0];
			state[4 * i + 0] = tmp;
		}
	}
}

u8 gmul(u8 a, u8 b)
{
	u8 p = 0;
	u8 i;
	//while (b) {
	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		if (a & 0x80) {
			a = (a << 1) ^ 0x1b;
		} else {
			a <<= 1;
		}
		b >>= 1;
	}

	return p;
}

void coef_mult(u8 *a, u8 *b, u8 *d)
{
	d[0] =
		gmul(a[0],b[0])^
		gmul(a[3],b[1])^
		gmul(a[2],b[2])^
		gmul(a[1],b[3]);
	d[1] =
		gmul(a[1],b[0])^
		gmul(a[0],b[1])^
		gmul(a[3],b[2])^
		gmul(a[2],b[3]);
	d[2] =
		gmul(a[2],b[0])^
		gmul(a[1],b[1])^
		gmul(a[0],b[2])^
		gmul(a[3],b[3]);
	d[3] =
		gmul(a[3],b[0])^
		gmul(a[2],b[1])^
		gmul(a[1],b[2])^
		gmul(a[0],b[3]);
}
/*******************************************************************************
func:
             mix_columns
description:
             all columns of state mix with another
param:
             state pointer to state
*******************************************************************************/
void mix_columns(u8 *state)
{
	u8 a[] = {
		0x02, 0x01, 0x01, 0x03,
	};
	u8 col[4] = {0};
	u8 res[4];
	u8 i, j;
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[4 * i + j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[4 * i + j] = res[i];
		}
	}
}

/*******************************************************************************
func:
             inv_mix_columns
description:
             all columns of state mix with another
param:
             state pointer to state
*******************************************************************************/
void inv_mix_columns(u8 *state)
{
	u8 a[] = {
		0x0e, 0x09, 0x0d, 0x0b,
	};
	u8 col[4] = {0};
	u8 res[4];
	u8 i, j;
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[4 * i + j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[4 * i + j] = res[i];
		}
	}
}
void rot_word(u8 *w)
{
	u8 tmp;
	u8 i;

	tmp = w[0];
	for (i = 0; i < 3; i++) {
		w[i] = w[i+1];
	}

	w[3] = tmp;
}
void sub_word(u8 *w)
{
	u8 i;
	for (i = 0; i < 4; i++) {
		w[i] = s_box[16*((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
	}
}
u8 *Rcon(u8 i)
{
	if (i == 1) {
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	} else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i-1 > 0) {
			R[0] = gmul(R[0], 0x02);
			i--;
		}
	}

	return R;
}
void coef_add(u8 a[], u8 b[], u8 d[])
{
	d[0] = a[0]^b[0];
	d[1] = a[1]^b[1];
	d[2] = a[2]^b[2];
	d[3] = a[3]^b[3];
}
/*******************************************************************************
func:
             key_expansion
description:
             generate 4 * (Nr + 1) 32-bit word keys
param:
             pkey: pointer to key(length is 128, 192, 256 int bit)
             w:    pointer to result key
*******************************************************************************/
void key_expansion(u8 *pkey, u8 *w)
{
	Nb = 4;
	Nr = 10;
	Nk = 4;

	u8 tmp[4];
	u8 i;
	u8 len = Nb * (Nr + 1);

	for (i = 0; i < Nk; i++) {
		w[4*i+0] = pkey[4*i+0];
		w[4*i+1] = pkey[4*i+1];
		w[4*i+2] = pkey[4*i+2];
		w[4*i+3] = pkey[4*i+3];
	}

	for (i = Nk; i < len; i++) {
		tmp[0] = w[4*(i-1)+0];
		tmp[1] = w[4*(i-1)+1];
		tmp[2] = w[4*(i-1)+2];
		tmp[3] = w[4*(i-1)+3];

		if (i%Nk == 0) {
			rot_word(tmp);
			sub_word(tmp);
			coef_add(tmp, Rcon(i/Nk), tmp);
		} else if (Nk > 6 && i%Nk == 4) {
			sub_word(tmp);
		}
		w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
		w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
		w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
		w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
	}
}

/*******************************************************************************
func:
             aes_enc_block
description:
             encrypt one block by aes
param:
             pdin: pointer to indata (length is 16 int byte)
             pkey: pointer to key(length is 128, 192, 256 int bit)
             keywidth: 128, 192, 256
             pdout: pointer to outdata
*******************************************************************************/
u32 aes_enc_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout)
{
	u8 i, j;
	u8 state[16] ={0};

	switch (keywidth)
	{
	case AES_KEYWIDTH_128:
		Nk = 4;
		Nr = 10;
		break;
	case AES_KEYWIDTH_192:
		Nk = 6;
		Nr = 12;
		break;
	case AES_KEYWIDTH_256:
		Nk = 8;
		Nr = 14;
		break;
	default:
		break;
	}

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[4 * i + j] = pdin[4 * j + i];
		}
	}

	u8 *w = (u8 *)malloc(4 * (Nr + 1) * sizeof(u32));
	key_expansion(pkey, w);

	add_round_key(state, w, 0);

	for (i = 1; i < Nr; i++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, w, i);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, w, Nr);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			pdout[4 * i + j] = state[4 * j + i];
		}
	}

	return OK;
}

/*******************************************************************************
func:
             aes_dec_block
description:
             encrypt one block by aes
param:
             pdin: pointer to indata (length is 16 int byte)
             pkey: pointer to key(length is 128, 192, 256 int bit)
             keywidth: 128, 192, 256
             pdout: pointer to outdata
*******************************************************************************/
u32 aes_dec_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout)
{
	u8 i, j;
	u8 state[AES_BLOCK_LEN] = { 0 };

	switch (keywidth)
	{
	case AES_KEYWIDTH_128:
		Nk = 4;
		Nr = 10;
		break;
	case AES_KEYWIDTH_192:
		Nk = 6;
		Nr = 12;
		break;
	case AES_KEYWIDTH_256:
		Nk = 8;
		Nr = 14;
		break;
	default:
		break;
	}

	for (i = 0; i < 4; i ++) {
		for (j = 0; j < 4; j++) {
			state[4 * i + j] = pdin[4 * j + i];
		}
	}

	u8 *w = (u8 *)malloc(4 * (Nr + 1) * sizeof(u32));
	key_expansion(pkey, w);

	add_round_key(state, w, Nr);

	for (i = Nr - 1; i > 0; i--) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, w, i);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, w, 0);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			pdout[4 * i + j] = state[4 * j + i];
		}
	}

	return OK;
}

u32 aes_check_param(aes_param *paesparam)
{
	if (NULL == paesparam) {
		printf("error paesparam\n");
		return ERROR;
	}
	if ((AES_MODE_ECB != paesparam->mode) 
		&& (AES_MODE_CBC != paesparam->mode)) {
		printf("error mode\n");
		return ERROR;
	}
	if ((AES_PADDING_00 != paesparam->padding) 
		&& (AES_PADDING_80 != paesparam->padding)) {
		printf("error padding\n");
		return ERROR;
	}
	if ((AES_DIR_ENCRYPT != paesparam->direction) 
		&& (AES_DIR_DECRYPT != paesparam->direction)) {
		printf("error direction\n");
		return ERROR;
	}
	if ((AES_KEYWIDTH_128 != paesparam->keywidth) 
		&& (AES_KEYWIDTH_192 != paesparam->keywidth) 
		&& (AES_KEYWIDTH_256 != paesparam->keywidth)) {
		printf("error keywidth\n");
		return ERROR;
	}
	if (NULL == paesparam->pkey || NULL == paesparam->pdin || NULL == paesparam->pdinlen 
		|| NULL == paesparam->pdout || NULL == paesparam->pdoutlen) {
		printf("error ptr\n");
		return ERROR;
	}
	if (*paesparam->pdoutlen < round_up(*paesparam->pdinlen, AES_BLOCK_LEN)) {
		printf("error outlen\n");
		return ERROR;
	}
	if (AES_DIR_DECRYPT == paesparam->direction) {
		if (*paesparam->pdinlen % AES_BLOCK_LEN) {
			printf("error dinlen when decrypt\n");
			return ERROR;
		}
	}

	return OK;
}
/*******************************************************************************
func:
             aes_cipher
description:
             enc/dec by aes
param:
             pdin: pointer to indata (length is 16 int byte)
             pkey: pointer to key(length is 128, 192, 256 int bit)
             keywidth: 128, 192, 256
             pdout: pointer to outdata
*******************************************************************************/
u32 aes_cipher(aes_param *paesparam)
{
	u32 ret = ERROR;

	u32 i;
	u32 blknum = 0;
	u32 rlen = 0;
	u32 padding_flag = 0;
	u8 buf[AES_BLOCK_LEN] = { 0 };

	u8 *pdin = paesparam->pdin;
	u8 *pdout = paesparam->pdout;

	if (0 == *paesparam->pdinlen) {
		printf("do nothing\n");
		return OK;
	}
	ret = aes_check_param(paesparam);
	if (OK != ret) {
		printf("error check param\n");
		return ret;
	}

	/* padding */
	blknum = *paesparam->pdinlen / AES_BLOCK_LEN;
	rlen = *paesparam->pdinlen % AES_BLOCK_LEN;
	if (0 != rlen) {
		ret = memcpy(buf, paesparam->pdin + blknum * AES_BLOCK_LEN, rlen);
		if (OK != ret) {
			printf("aes_cipher: error memcpy\n");
			return ERROR;
		}
		if (AES_PADDING_80 == paesparam->padding) {
			buf[rlen] = 0x80;
		}
		padding_flag++;
	}

	if (AES_DIR_ENCRYPT == paesparam->direction) {
		for (i = 0; i < blknum; i++) {
			aes_enc_block(pdin, 
					paesparam->pkey, 
					paesparam->keywidth, 
					pdout);
			printf("padding no\n");
			printf("blkidx=%d\n", i);
			dump_mem(pdout, AES_BLOCK_LEN);
			pdin += AES_BLOCK_LEN;
			pdout += AES_BLOCK_LEN;
		}
		if (padding_flag) {
			aes_enc_block(buf,
					paesparam->pkey, 
					paesparam->keywidth, 
					pdout);
			printf("padding yes\n");
			printf("blkidx=%d\n", i);
			dump_mem(pdout, AES_BLOCK_LEN);
			*paesparam->pdoutlen = AES_BLOCK_LEN * (blknum + 1);
		} else {
			*paesparam->pdoutlen = AES_BLOCK_LEN * blknum;
		}
	}
	if (AES_DIR_DECRYPT == paesparam->direction) {
		for (i = 0; i < blknum; i++) {
			aes_dec_block(pdin,
					paesparam->pkey,
					paesparam->keywidth,
					pdout);
			pdin += AES_BLOCK_LEN;
			pdout += AES_BLOCK_LEN;
		}
		*paesparam->pdoutlen = AES_BLOCK_LEN * blknum;
	}

	return ret;
}

void print_state(u8 *state)
{
	u8 i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			printf("0x%x,", state[4 * i + j]);
		}
		printf("\n");
	}
}

extern u8 TEST_IN[];
extern u8 TEST_KEY[];
extern u8 TEST_OUT[];
int main(void)
{
	//aes_enc_block(TEST_IN, TEST_KEY, AES_KEYWIDTH_128, TEST_OUT);
	//dump_mem(TEST_OUT, AES_BLOCK_LEN);

	//aes_dec_block(TEST_OUT, TEST_KEY, AES_KEYWIDTH_128, TEST_OUT);
	//dump_mem(TEST_OUT, AES_BLOCK_LEN);
	test_aes_cipher_item(0);

	return OK;
}
