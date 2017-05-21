#ifndef _AES_H_
#define _AES_H_

#include "types.h"
/*******************************************************************************
 *                               Macro Defination
*******************************************************************************/
#define OK    (0x0)
#define ERROR (0x1)

#define BITS_PER_BYTE       (8)
#define AES_BLOCK_LEN       (16)
#define AES_KEYWIDTH_128    (128)
#define AES_KEYWIDTH_192    (192)
#define AES_KEYWIDTH_256    (256)
#define AES_MODE_ECB        (0x0)
#define AES_MODE_CBC        (0x1)
#define AES_PADDING_00      (0x0)
#define AES_PADDING_80      (0x1)
#define AES_DIR_ENCRYPT     (0x0)
#define AES_DIR_DECRYPT     (0x1)

/*******************************************************************************
 *                               Gloable Varible
*******************************************************************************/
#if 0
typedef struct aes_ctx {
	u32 mode;                     /* ecb, cbc         */
	u32 padding;                  /* pad 00 or 80     */
	u32 blen;                     /* len of block buf */
	u8  bbuf[AES_BLOCK_LEN];      /* block buf        */
	u8  ivbuf[AES_BLOCK_LEN];     /* iv buf when cbc  */
} aes_ctx;
#endif

typedef struct aes_param {
	u32 mode;               /* ecb, cbc                         */
	u32 padding;            /* 00 or 80                         */
	u32 direction;          /* encrypt or decrypt               */
	u32 keywidth;           /* 128, 192, 256                    */
	u8  *pkey;              /* pointer to key                   */
	u8  *pdin;              /* pointer to input data            */
	u32 *pdinlen;           /* pointer to length of input data  */
	u8  *pdout;             /* pointer to output data           */
	u32 *pdoutlen;          /* pointer to length of output data */
} aes_param;

/*******************************************************************************
 *                         Declarartion of Function
*******************************************************************************/
u32 round_up(u32 value, u32 modulus);
u32 memcpy(u8 *dst, u8 *src, u32 len);
void print_mem(u8 *pmem, u32 memlen);
/*******************************************************************************
 *                         Declarartion of Function
*******************************************************************************/
u32 aes_enc_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout);
u32 aes_dec_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout);
u32 aes_cipher(aes_param *paesparam);
#if 0
u32 aes_init(aes_ctx *pctx);
u32 aes_update(aes_ctx *ptx, u8 *pdin, u32 *pdinlen, u8 *pdout, u32 *pdoutlen);
u32 aes_finish(aes_ctx *pctx, u8 *pdout, u32 *pdoutlen);
#endif

#endif

