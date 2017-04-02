#ifndef _AES_H_
#define _AES_H_

#include "types.h"
#define OK    (0x0)
#define ERROR (0x1)

#define AES_BLOCK_LEN       (0x16)
#define AES_KEYWIDTH_128    (128)
#define AES_KEYWIDTH_192    (192)
#define AES_KEYWIDTH_256    (256)

/**************************************************************
func:   
             aes_enc_block
description: 
             encrypt one block by aes
param:
             pdin: pointer to indata (length is 16 int byte)
             pkey: pointer to key(length is 128, 192, 256 int bit)
             keywidth: 128, 192, 256
             pdout: pointer to outdata
**************************************************************/
u32 aes_enc_block(u8 *pdin, u8 *pkey, u32 keywidth, u8 *pdout);

#endif

