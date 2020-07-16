/*
 *  drivers/mtd/nand_bbt.c
 *
 *  Overview:
 *   Bad block table support for the NAND driver
 *
 *  Copyright © 2004 Thomas Gleixner (tglx@linutronix.de)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Description:
 *
 * When nand_scan_bbt is called, then it tries to find the bad block table
 * depending on the options in the BBT descriptor(s). If no flash based BBT
 * (NAND_BBT_USE_FLASH) is specified then the device is scanned for factory
 * marked good / bad blocks. This information is used to create a memory BBT.
 * Once a new bad block is discovered then the "factory" information is updated
 * on the device.
 * If a flash based BBT is specified then the function first tries to find the
 * BBT on flash. If a BBT is found then the contents are read and the memory
 * based BBT is created. If a mirrored BBT is selected then the mirror is
 * searched too and the versions are compared. If the mirror has a greater
 * version number, then the mirror BBT is used to build the memory based BBT.
 * If the tables are not versioned, then we "or" the bad block information.
 * If one of the BBTs is out of date or does not exist it is (re)created.
 * If no BBT exists at all then the device is scanned for factory marked
 * good / bad blocks and the bad block tables are created.
 *
 * For manufacturer created BBTs like the one found on M-SYS DOC devices
 * the BBT is searched and read but never created
 *
 * The auto generated bad block table is located in the last good blocks
 * of the device. The table is mirrored, so it can be updated eventually.
 * The table is marked in the OOB area with an ident pattern and a version
 * number which indicates which of both tables is more up to date. If the NAND
 * controller needs the complete OOB area for the ECC information then the
 * option NAND_BBT_NO_OOB should be used (along with NAND_BBT_USE_FLASH, of
 * course): it moves the ident pattern and the version byte into the data area
 * and the OOB area will remain untouched.
 *
 * The table uses 2 bits per block
 * 11b:		block is good
 * 00b:		block is factory marked bad
 * 01b, 10b:	block is marked bad due to wear
 *
 * The memory bad block table uses the following scheme:
 * 00b:		block is good
 * 01b:		block is marked bad due to wear
 * 10b:		block is reserved (to protect the bbt area)
 * 11b:		block is factory marked bad
 *
 * Multichip devices like DOC store the bad block info per floor.
 *
 * Following assumptions are made:
 * - bbts start at a page boundary, if autolocated on a block boundary
 * - the space necessary for a bbt in FLASH does not exceed a block boundary
 *
 */

#define  __SYLIXOS_KERNEL
#include "SylixOS.h"
#include "malloc.h"
#include "linux/compat.h"
#include "linux/mtd/mtd.h"
#include "linux/mtd/bbm.h"
#include "linux/mtd/nand.h"
#include "linux/mtd/nand_ecc.h"
#include "linux/bitops.h"
#include "string.h"

#include "errno.h"

/*********************************************************************************************************
** 函数名称: check_bytes8
** 功能描述: 检测指定长度、指定起始地址的数据缓冲区数据和指定的数据是否相等
** 输	 入: start - 需要校验的起始数据地址
**         : value - 检测的目标值
**         : bytes - 需要检测的数据字节数
** 输	 出: NULL - 所有的数据都和指定目标值是否相等
**         : void * - 和指定的目标值不相等的内存地址
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static void *check_bytes8(const u8 *start, u8 value, unsigned int bytes)
{
    while (bytes) {
        if (*start != value)
            return (void *)start;
        start++;
        bytes--;
    }
    return NULL;
}
/**
 * memchr_inv - Find an unmatching character in an area of memory.
 * @start: The memory area
 * @c: Find a character other than c
 * @bytes: The size of the area.
 *
 * returns the address of the first character other than @c, or %NULL
 * if the whole buffer contains just @c.
 */
/*********************************************************************************************************
** 函数名称: memchr_inv
** 功能描述: 检测指定长度、指定起始地址的数据缓冲区数据和指定的数据是否相等
** 输	 入: start - 需要校验的起始数据地址
**         : value - 检测的目标值
**         : bytes - 需要检测的数据字节数
** 输	 出: NULL - 所有的数据都和指定目标值是否相等
**         : void * - 和指定的目标值不相等的内存地址
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
void *memchr_inv(const void *start, int c, size_t bytes)
{
    u8 value = c;
    u64 value64;
    unsigned int words, prefix;

    if (bytes <= 16)
        return check_bytes8(start, value, bytes);

    value64 = value;
    value64 |= value64 << 8;
    value64 |= value64 << 16;
    value64 |= value64 << 32;

    prefix = (unsigned long)start % 8;
    if (prefix) {
        u8 *r;

        prefix = 8 - prefix;
        r = check_bytes8(start, value, prefix);
        if (r)
            return r;
        start += prefix;
        bytes -= prefix;
    }

    words = bytes / 8;

    while (words) {
        if (*(u64 *)start != value64)
            return check_bytes8(start, value, 8);
        start += 8;
        words--;
    }

    return check_bytes8(start, value, bytes % 8);
}

/*********************************************************************************************************
** 函数名称: check_pattern_no_oob
** 功能描述: 判断指定的缓冲区中是否包含指定的 bbt 描述符的 pattern 数据
** 输	 入: buf - 需要判断的缓冲区起始地址
**         : td - 当前 nand 的 bbt 描述符
** 输	 出: 0 - 当前缓冲区“包含”指定的 pattern 数据
**         : -1 - 当前缓冲区“不包含”指定的 pattern 数据
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int check_pattern_no_oob(uint8_t *buf, struct nand_bbt_descr *td)
{
	if (memcmp(buf, td->pattern, td->len))
		return -1;
	return 0;
}

/**
 * check_pattern - [GENERIC] check if a pattern is in the buffer
 * @buf: the buffer to search
 * @len: the length of buffer to search
 * @paglen: the pagelength
 * @td: search pattern descriptor
 *
 * Check for a pattern at the given place. Used to search bad block tables and
 * good / bad block identifiers. If the SCAN_EMPTY option is set then check, if
 * all bytes except the pattern area contain 0xff.
 */
/*********************************************************************************************************
** 函数名称: check_pattern
** 功能描述: 判断指定的存储页缓冲区中是否包含指定的 bbt 描述符的 pattern 数据
**         : 这个函数除了会判断 pattern 数据，还可以根据 bbt 描述符校验其他位置处的数据
** 输	 入: buf - 需要判断的数据页缓冲区起始地址（包含存储数据和 OOB 数据）
**         : len - 数据页缓冲区长度（包含存储数据和 OOB 数据）
**         : paglen - 数据页存储数据空间大小
**         : td - 当前 nand 的 bbt 描述符
** 输	 出: 0 - 当前页缓冲区“包含”指定的 pattern 数据
**         : -1 - 当前页缓冲区“不包含”指定的 pattern 数据
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int check_pattern(uint8_t *buf, int len, int paglen, struct nand_bbt_descr *td)
{
	int end = 0;
	uint8_t *p = buf;

	if (td->options & NAND_BBT_NO_OOB)
		return check_pattern_no_oob(buf, td);

	end = paglen + td->offs;

	/* 判断当前指定的 nand 存储页是否为空，即当前存储页缓冲区中除了 pattern 数据，其他位置是否全为 0xFF */
	if (td->options & NAND_BBT_SCANEMPTY)
		if (memchr_inv(p, 0xff, end))
			return -1;

    /* 把 p 指针移动到当前存储页缓冲区中存储 bbt pattern 数据的位置处 */
	p += end;

	/* Compare the pattern */
	if (memcmp(p, td->pattern, td->len))
		return -1;

	/* 判断当前指定的 nand 存储页是否为空，即当前存储页缓冲区中除了 pattern 数据，其他位置是否全为 0xFF */
	if (td->options & NAND_BBT_SCANEMPTY) {
		p += td->len;
		end += td->len;
		if (memchr_inv(p, 0xff, len - end))
			return -1;
	}
	
	return 0;
}

/**
 * check_short_pattern - [GENERIC] check if a pattern is in the buffer
 * @buf: the buffer to search
 * @td:	search pattern descriptor
 *
 * Check for a pattern at the given place. Used to search bad block tables and
 * good / bad block identifiers. Same as check_pattern, but no optional empty
 * check.
 */
/*********************************************************************************************************
** 函数名称: check_short_pattern
** 功能描述: 判断指定的存储页缓冲区中是否包含指定的 bbt 描述符的 pattern 数据
**         : 这个函数只会判断当前存储页中的 pattern 数据
** 输	 入: buf - 需要判断的数据页缓冲区起始地址（包含存储数据和 OOB 数据）
**         : td - 当前 nand 的 bbt 描述符
** 输	 出: 0 - 当前页缓冲区“包含”指定的 pattern 数据
**         : -1 - 当前页缓冲区“不包含”指定的 pattern 数据
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int check_short_pattern(uint8_t *buf, struct nand_bbt_descr *td)
{
	/* Compare the pattern */
	if (memcmp(buf + td->offs, td->pattern, td->len))
		return -1;
	return 0;
}

/**
 * add_marker_len - compute the length of the marker in data area
 * @td: BBT descriptor used for computation
 *
 * The length will be 0 if the marker is located in OOB area.
 */
/*********************************************************************************************************
** 函数名称: add_marker_len
** 功能描述: 计算指定的 bbt 描述符的 marker 数据如果存储在存储页的数据存储区中（inband），会占用的字节数
** 输	 入: td - bbt 描述符指针
** 输	 出: len - bbt 需要占用的空间字节数
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static u32 add_marker_len(struct nand_bbt_descr *td)
{
	u32 len;

	if (!(td->options & NAND_BBT_NO_OOB))
		return 0;

	len = td->len;
	if (td->options & NAND_BBT_VERSION)
		len++;
	return len;
}

/**
 * read_bbt - [GENERIC] Read the bad block table starting from page
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @page: the starting page
 * @num: the number of bbt descriptors to read
 * @td: the bbt describtion table
 * @offs: offset in the memory table
 *
 * Read the bad block table starting from page.
 */
/*********************************************************************************************************
** 函数名称: read_bbt
** 功能描述: 根据 nand 中存储的 bbt 数据更新 ram 中的 bbt 数据，具体如下：
**         : 从指定 mtd 设备的指定起始页号（pgae）对应的存储页中读取指定数据块个数（num）对应的坏块标志
**         : 数据到指定的缓冲区（buf）中，并判断这些数据块中是否有坏块，如果有，则更新内存 bbt 表中的数据
**         : 把对应数据块在 bbt 中的数据设置为坏块标记
** 输	 入: mtd - mtd 设备信息
**         : buf - 用来存储读取到的存储页数据的缓冲区
**         : page - 读取“坏块标志”数据的起始页号
**         : num - 表示需要读取多少个数据块的“坏块标志”数据
**         : td - 当前 nand 的 bbt 描述符
**         : offs - 当前读取的起始坏块标志数据在内存 bbt 表中的其实偏移量
** 输	 出: ret - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int read_bbt(struct mtd_info *mtd, uint8_t *buf, int page, int num,
		struct nand_bbt_descr *td, int offs)
{
	int res, ret = 0, i, j, act = 0;
	struct nand_chip *this = mtd->priv;
	size_t retlen, len, totlen;
	loff_t from;

	/* 表示一个存储数据块在 bbt 中占用的数据 bit 数 */
	int bits = td->options & NAND_BBT_NRBITS_MSK;

    /* 表示一个存储数据块在 bbt 中的数据的掩码值 */
	uint8_t msk = (uint8_t)((1 << bits) - 1);
	
	u32 marker_len;
	int reserved_block_code = td->reserved_block_code;

    /* 计算本次读取操作需要读取的 bbt 数据字节数 */
	totlen = (num * bits) >> 3;

	/* 计算指定的 bbt 描述符的 marker 数据如果存储在存储页的数据存储区中（inband），会占用的字节数 */
	marker_len = add_marker_len(td);

	/* 计算当前起始页在 nand 中的全局偏移量 */
	from = ((loff_t)page) << this->page_shift;

	while (totlen) {

	    /* 把 totlen 长度按照擦除块大小进行切割并向下取小 */
		len = min(totlen, (size_t)(1 << this->bbt_erase_shift));

	    /* 跳过起始存储页中的 bbt marker 数据 */
		if (marker_len) {
			/*
			 * In case the BBT marker is not in the OOB area it
			 * will be just in the first page.
			 */
			len -= marker_len;
			from += marker_len;
			marker_len = 0;
		}

		/* 用 mtd->_read 接口尝试从指定的 mtd 设备指定位置处读出指定长度的数据，并返回实际读到的数据长度 */
		res = mtd_read(mtd, from, len, &retlen, buf);
		if (res < 0) {
			if (mtd_is_eccerr(res)) {
				pr_info("nand_bbt: ECC error in BBT at "
					"0x%012llx\n", from & ~mtd->writesize);
				return res;
			} else if (mtd_is_bitflip(res)) {
				pr_info("nand_bbt: corrected error in BBT at "
					"0x%012llx\n", from & ~mtd->writesize);
				ret = res;
			} else {
				pr_info("nand_bbt: error reading BBT\n");
				return res;
			}
		}

		/* Analyse data */
		/* 分别遍历从当前指定的 nand 存储块中读出的每一个字节数据 */
		for (i = 0; i < len; i++) {
			uint8_t dat = buf[i];

            /* 分别遍历当前字节中每个存储块对应的坏块标志数据 */
			for (j = 0; j < 8; j += bits, act += 2) {
				uint8_t tmp = (dat >> j) & msk;

			    /* 如果坏块标志数据为全 F，则表示是一个好的数据块 */
				if (tmp == msk)
					continue;

				if (reserved_block_code && (tmp == reserved_block_code)) {
					pr_info("nand_read_bbt: reserved block at 0x%012llx\n",
						 (loff_t)((offs << 2) + (act >> 1)) << this->bbt_erase_shift);
					this->bbt[offs + (act >> 3)] |= 0x2 << (act & 0x06);
					mtd->ecc_stats.bbtblocks++;
					continue;
				}
				
				pr_info("nand_read_bbt: Bad block at 0x%012llx\n",
					(loff_t)((offs << 2) + (act >> 1))
					<< this->bbt_erase_shift);
				
				/* Factory marked bad or worn out?
			     * The table uses 2 bits per block
                 * 11b:		  block is good
                 * 00b:		  block is factory marked bad
                 * 01b, 10b : block is marked bad due to wear
                 *
                 * The memory bad block table uses the following scheme:
                 * 00b:		  block is good
                 * 01b:		  block is marked bad due to wear
                 * 10b:		  block is reserved (to protect the bbt area)
                 * 11b:		  block is factory marked bad */
				if (tmp == 0)
					this->bbt[offs + (act >> 3)] |= 0x3 << (act & 0x06);
				else
					this->bbt[offs + (act >> 3)] |= 0x1 << (act & 0x06);

				mtd->ecc_stats.badblocks++;
			}
		}
		
		totlen -= len;
		from += len;
	}
	
	return ret;
}

/**
 * read_abs_bbt - [GENERIC] Read the bad block table starting at a given page
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @td: descriptor for the bad block table
 * @chip: read the table for a specific chip, -1 read all chips; applies only if
 *        NAND_BBT_PERCHIP option is set
 *
 * Read the bad block table for all chips starting at a given page. We assume
 * that the bbt bits are in consecutive order.
 */
/*********************************************************************************************************
** 函数名称: read_abs_bbt
** 功能描述: 根据 nand 中存储的 bbt 数据更新 ram 中的 bbt 数据
** 输	 入: mtd - mtd 设备信息
**         : buf - 用来存储读取到的存储页数据的缓冲区
**         : td - 当前 nand 的 bbt 描述符
**         : chip - 表示想要读取那个 nand 的 bbt 数据，-1 表示读取所有 nand 的 bbt 数据
** 输	 出: ret - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int read_abs_bbt(struct mtd_info *mtd, uint8_t *buf, struct nand_bbt_descr *td, int chip)
{
	struct nand_chip *this = mtd->priv;
	int res = 0, i;

	/* 表示每个 nand 存储器的 bbt 数据都存储在各自的存储空间中 */
	if (td->options & NAND_BBT_PERCHIP) {
		int offs = 0;
		for (i = 0; i < this->numchips; i++) {
			if (chip == -1 || chip == i)
				res = read_bbt(mtd, buf, td->pages[i],
					this->chipsize >> this->bbt_erase_shift,
					td, offs);
			if (res)
				return res;
			offs += this->chipsize >> (this->bbt_erase_shift + 2);
		}

    /* 表示所有 nand 存储器的 bbt 数据都存储在第一个 nand 的存储空间中 */
	} else {
		res = read_bbt(mtd, buf, td->pages[0],
				mtd->size >> this->bbt_erase_shift, td, 0);
		if (res)
			return res;
	}
	
	return 0;
}

/* BBT marker is in the first page, no OOB */
/*********************************************************************************************************
** 函数名称: scan_read_data
** 功能描述: 从指定的 mtd 设备的指定偏移量位置处读取 bbt pattern 数据到指定的缓冲区中
** 输	 入: mtd - mtd 设备信息
**         : buf - 用来存储读取到的存储页数据的缓冲区
**         : offs - 读取起始偏移量（全局偏移量）
**         : td - 当前 nand 的 bbt 描述符
** 输	 出: ret_code - 读取状态
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_read_data(struct mtd_info *mtd, uint8_t *buf, loff_t offs,
			 struct nand_bbt_descr *td)
{
	size_t retlen;
	size_t len;

	len = td->len;
	if (td->options & NAND_BBT_VERSION)
		len++;

	return mtd_read(mtd, offs, len, &retlen, buf);
}

/**
 * scan_read_oob - [GENERIC] Scan data+OOB region to buffer
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @offs: offset at which to scan
 * @len: length of data region to read
 *
 * Scan read data from data+OOB. May traverse multiple pages, interleaving
 * page,OOB,page,OOB,... in buf. Completes transfer and returns the "strongest"
 * ECC condition (error or bitflip). May quit on the first (non-ECC) error.
 */
/*********************************************************************************************************
** 函数名称: scan_read_oob
** 功能描述: 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据（存储数据和 OOB 数据）到指定的缓冲区中
** 注     释: Scan read data from data+OOB. May traverse multiple pages, interleaving 
**         : page, OOB, page, OOB... in buf.
** 输	 入: mtd - mtd 设备信息
**         : buf - 用来存储读取到的存储页数据的缓冲区
**         : offs - 读取起始偏移量（全局偏移量）
**         : len - 需要读取的数据字节数
** 输	 出: ret_code - 读取状态
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_read_oob(struct mtd_info *mtd, uint8_t *buf, loff_t offs,
			 size_t len)
{
	struct mtd_oob_ops ops;
	int res, ret = 0;

	ops.mode = MTD_OPS_PLACE_OOB;
	ops.ooboffs = 0;
	ops.ooblen = mtd->oobsize;

	while (len > 0) {
		ops.datbuf = buf;
		ops.len = min(len, (size_t)mtd->writesize);
		ops.oobbuf = buf + ops.len;

		res = mtd_read_oob(mtd, offs, &ops);
		if (res) {
			if (!mtd_is_bitflip_or_eccerr(res))
				return res;
			else if (mtd_is_eccerr(res) || !ret)
				ret = res;
		}

		buf += mtd->oobsize + mtd->writesize;
		len -= mtd->writesize;
		offs += mtd->writesize;
	}
	return ret;
}

/*********************************************************************************************************
** 函数名称: scan_read
** 功能描述: 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据到指定的缓冲区中
** 注     释: 会根据 bbt 描述符选项数据决定是否读取 OOB 数据
** 输     入: mtd - mtd 设备信息
** 		   : buf - 用来存储读取到的存储页数据的缓冲区
** 		   : offs - 读取起始偏移量（全局偏移量）
** 		   : len - 需要读取的数据字节数
** 		   : td - 当前 nand 的 bbt 描述符
** 输     出: ret_code - 读取状态
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_read(struct mtd_info *mtd, uint8_t *buf, loff_t offs,
			 size_t len, struct nand_bbt_descr *td)
{
	if (td->options & NAND_BBT_NO_OOB)
		return scan_read_data(mtd, buf, offs, td);
	else
		return scan_read_oob(mtd, buf, offs, len);
}

/* Scan write data with oob to flash */
/*********************************************************************************************************
** 函数名称: scan_write_bbt
** 功能描述: 向指定的 mtd 设备的指定偏移量位置处写入指定长度的数据（存储数据和 OOB 数据）
** 输     入: mtd - mtd 设备信息
** 		   : offs - 写入数据起始偏移量（全局偏移量）
** 		   : len - 想要写入的存储数据长度
** 		   : buf - 想要写入的存储数据缓冲区
** 		   : oob - 想要写入的 OOB 数据缓冲区
** 输     出: ret_code - 写入状态
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_write_bbt(struct mtd_info *mtd, loff_t offs, size_t len,
			  uint8_t *buf, uint8_t *oob)
{
	struct mtd_oob_ops ops;

	ops.mode = MTD_OPS_PLACE_OOB;
	ops.ooboffs = 0;
	ops.ooblen = mtd->oobsize;
	ops.datbuf = buf;
	ops.oobbuf = oob;
	ops.len = len;

	return mtd_write_oob(mtd, offs, &ops);
}

/*********************************************************************************************************
** 函数名称: bbt_get_ver_offs
** 功能描述: 根据指定的 bbt 描述符获取指定的 mtd 设备的 bbt 版本号偏移量
** 输	 入: mtd - mtd 设备信息
**		   : td - 当前 nand bbt 描述符
** 输	 出: ver_offs - 读取到的 bbt 版本偏移量
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static u32 bbt_get_ver_offs(struct mtd_info *mtd, struct nand_bbt_descr *td)
{
	u32 ver_offs = td->veroffs;

	if (!(td->options & NAND_BBT_NO_OOB))
		ver_offs += mtd->writesize;
	return ver_offs;
}

/**
 * read_abs_bbts - [GENERIC] Read the bad block table(s) for all chips starting at a given page
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @td: descriptor for the bad block table
 * @md:	descriptor for the bad block table mirror
 *
 * Read the bad block table(s) for all chips starting at a given page. We
 * assume that the bbt bits are in consecutive order.
 */
/*********************************************************************************************************
** 函数名称: read_abs_bbts
** 功能描述: 根据指定的 bbt 描述符读取指定的 mtd 设备的 bbt 数据到指定的缓冲区中
** 注     释: 如果同时读取主 bbt 描述符和镜像 bbt 描述符，则以镜像 bbt 描述符优先
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : td - 当前 nand 的主 bbt 描述符
**		   : md - 当前 nand 的镜像 bbt 描述符
** 输	 出: 
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static void read_abs_bbts(struct mtd_info *mtd, uint8_t *buf,
			  struct nand_bbt_descr *td, struct nand_bbt_descr *md)
{
	struct nand_chip *this = mtd->priv;

	/* Read the primary version, if available */
	if (td->options & NAND_BBT_VERSION) {
		scan_read(mtd, buf, (loff_t)td->pages[0] << this->page_shift,
			      mtd->writesize, td);
		td->version[0] = buf[bbt_get_ver_offs(mtd, td)];
		pr_info("Bad block table at page %d, version 0x%02X\n",
			 td->pages[0], td->version[0]);
	}

	/* Read the mirror version, if available */
	if (md && (md->options & NAND_BBT_VERSION)) {
		scan_read(mtd, buf, (loff_t)md->pages[0] << this->page_shift,
			      mtd->writesize, md);
		md->version[0] = buf[bbt_get_ver_offs(mtd, md)];
		pr_info("Bad block table at page %d, version 0x%02X\n",
			 md->pages[0], md->version[0]);
	}
}

/* Scan a given block full */
/*********************************************************************************************************
** 函数名称: scan_block_full
** 功能描述: 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据（存储数据和 OOB 数据）到指定的缓冲区中
**         : 并判断读取到缓冲区中数据和指定的 bbt 描述符的 pattern 数据是否匹配
** 输	 入: mtd - mtd 设备信息
**		   : bd - 当前 nand 的 bbt 描述符
**		   : offs - 读取起始偏移量（全局偏移量）
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : readlen - 需要读取的数据字节数
**		   : scanlen - 每个存储页的长度（存储数据加上 OOB 数据的和）
**		   : numpages - 需要扫描的存储页个数
** 输	 出: 0 - 和指定的 pattern 数据匹配
**         : -1 - 和指定的 pattern 数据“不”匹配
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_block_full(struct mtd_info *mtd, struct nand_bbt_descr *bd,
			   loff_t offs, uint8_t *buf, size_t readlen,
			   int scanlen, int numpages)
{
	int ret, j;

    /* 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据（存储数据和 OOB 数据）到指定的缓冲区中 */
	ret = scan_read_oob(mtd, buf, offs, readlen);
	/* Ignore ECC errors when checking for BBM */
	if (ret && !mtd_is_bitflip_or_eccerr(ret))
		return ret;

	for (j = 0; j < numpages; j++, buf += scanlen) {
		/* 判断指定的存储页缓冲区中是否包含指定的 bbt 描述符的 pattern 数据 */
		if (check_pattern(buf, scanlen, mtd->writesize, bd))
			return 1;
	}
	return 0;
}

/* Scan a given block partially */
/*********************************************************************************************************
** 函数名称: scan_block_fast
** 功能描述: 从指定的 mtd 设备的指定偏移量位置处读取指定个数的存储页的 OOB 数据并判断读取到的 OOB 数据
**         : 和指定的 bbt 描述符的 pattern 数据是否匹配
** 输	 入: mtd - mtd 设备信息
**		   : bd - 当前 nand 的 bbt 描述符
**		   : offs - 读取起始偏移量（全局偏移量）
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : numpages - 需要扫描的存储页个数
** 输	 出: 0 - 和指定的 pattern 数据匹配
**         : -1 - 和指定的 pattern 数据“不”匹配
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int scan_block_fast(struct mtd_info *mtd, struct nand_bbt_descr *bd,
			   loff_t offs, uint8_t *buf, int numpages)
{
	struct mtd_oob_ops ops;
	int j, ret;

	ops.ooblen = mtd->oobsize;
	ops.oobbuf = buf;
	ops.ooboffs = 0;
	ops.datbuf = NULL;
	ops.mode = MTD_OPS_PLACE_OOB;

	for (j = 0; j < numpages; j++) {
		/*
		 * Read the full oob until read_oob is fixed to handle single
		 * byte reads for 16 bit buswidth.
		 */
		/* 只读取 OOB 数据，所以速度比较快 */
		ret = mtd_read_oob(mtd, offs, &ops);
		/* Ignore ECC errors when checking for BBM */
		if (ret && !mtd_is_bitflip_or_eccerr(ret))
			return ret;

        /* 判断指定的存储页缓冲区中是否包含指定的 bbt 描述符的 pattern 数据 */
		if (check_short_pattern(buf, bd))
			return 1;

		offs += mtd->writesize;
	}
	return 0;
}

/**
 * create_bbt - [GENERIC] Create a bad block table by scanning the device
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @bd: descriptor for the good/bad block search pattern
 * @chip: create the table for a specific chip, -1 read all chips; applies only
 *        if NAND_BBT_PERCHIP option is set
 *
 * Create a bad block table by scanning the device for the given good/bad block
 * identify pattern.
 */
/*********************************************************************************************************
** 函数名称: create_bbt
** 功能描述: 根据指定的 bbt 描述符遍历指定的 mtd 设备存储块来创建内存中的 bbt 数据结构
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : bd - 当前 nand 的 bbt 描述符
**		   : chip - 需要创建 bbt 的芯片索引，-1 表示所有芯片
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int create_bbt(struct mtd_info *mtd, uint8_t *buf,
	struct nand_bbt_descr *bd, int chip)
{
	struct nand_chip *this = mtd->priv;
	int i, numblocks, numpages, scanlen;
	int startblock;
	loff_t from;
	size_t readlen;

	pr_info("Scanning device for bad blocks\n");

    /* 根据 bbt 选项数据确定本次需要在一个数据块内扫描几个存储页的数据 */
	if (bd->options & NAND_BBT_SCANALLPAGES)
		numpages = 1 << (this->bbt_erase_shift - this->page_shift);
	else if (bd->options & NAND_BBT_SCAN2NDPAGE)
		numpages = 2;
	else
		numpages = 1;

	if (!(bd->options & NAND_BBT_SCANEMPTY)) {
		/* We need only read few bytes from the OOB area */
		scanlen = 0;
		readlen = bd->len;
	} else {
		/* Full page content should be read */
		scanlen = mtd->writesize + mtd->oobsize;
		readlen = numpages * mtd->writesize;
	}

	if (chip == -1) {
		/*
		 * Note that numblocks is 2 * (real numblocks) here, see i+=2
		 * below as it makes shifting and masking less painful
		 */
		numblocks = mtd->size >> (this->bbt_erase_shift - 1);
		startblock = 0;
		from = 0;
	} else {
		if (chip >= this->numchips) {
			pr_warn("create_bbt(): chipnr (%d) > available chips (%d)\n",
			       chip + 1, this->numchips);
			return -EINVAL;
		}
		numblocks = this->chipsize >> (this->bbt_erase_shift - 1);
		startblock = chip * numblocks;
		numblocks += startblock;
		from = (loff_t)startblock << (this->bbt_erase_shift - 1);
	}

	if (this->bbt_options & NAND_BBT_SCANLASTPAGE)
		from += mtd->erasesize - (mtd->writesize * numpages);

	for (i = startblock; i < numblocks;) {
		int ret;

		BUG_ON(bd->options & NAND_BBT_NO_OOB);

		if (bd->options & NAND_BBT_SCANALLPAGES)
			/* 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据（存储数据和 OOB 数据）到指定的缓冲区中
               并判断读取到缓冲区中数据和指定的 bbt 描述符的 pattern 数据是否匹配 */
			ret = scan_block_full(mtd, bd, from, buf, readlen,
					      scanlen, numpages);
		else
			/* 从指定的 mtd 设备的指定偏移量位置处读取指定个数的存储页的 OOB 数据并判断读取到的 OOB 数据
               和指定的 bbt 描述符的 pattern 数据是否匹配 */
			ret = scan_block_fast(mtd, bd, from, buf, numpages);

		if (ret < 0)
			return ret;

        /* 如果当前遍历的存储块是坏块，则在内存中的 bbt 的对应位置设置坏块标志并统计当前芯片坏块计数 */
		if (ret) {
			this->bbt[i >> 3] |= 0x03 << (i & 0x6);
			pr_warn("Bad eraseblock %d at 0x%012llx\n",
				  i >> 1, (unsigned long long)from);
			mtd->ecc_stats.badblocks++;
		}

		i += 2;
		from += (1 << this->bbt_erase_shift);
	}
	return 0;
}

/**
 * search_bbt - [GENERIC] scan the device for a specific bad block table
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @td: descriptor for the bad block table
 *
 * Read the bad block table by searching for a given ident pattern. Search is
 * preformed either from the beginning up or from the end of the device
 * downwards. The search starts always at the start of a block. If the option
 * NAND_BBT_PERCHIP is given, each chip is searched for a bbt, which contains
 * the bad block information of this chip. This is necessary to provide support
 * for certain DOC devices.
 *
 * The bbt ident pattern resides in the oob area of the first page in a block.
 */
/*********************************************************************************************************
** 函数名称: search_bbt
** 功能描述: 根据指定的 bbt 描述符从指定的 mtd 设备中遍历查找 bbt 数据，并在 td 中记录读取到的 bbt 信息 
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : td - 当前 nand 的 bbt 描述符
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int search_bbt(struct mtd_info *mtd, uint8_t *buf, struct nand_bbt_descr *td)
{
	struct nand_chip *this = mtd->priv;
	int i, chips;
	int startblock, block, dir;
	int scanlen = mtd->writesize + mtd->oobsize;
	int bbtblocks;
	int blocktopage = this->bbt_erase_shift - this->page_shift;

	/* Search direction top -> down? */
	/* 根据当前 bbt 选项数据决定从哪个位置开始扫描存储在 nand 中的 bbt 数据 */
	if (td->options & NAND_BBT_LASTBLOCK) {
		startblock = (mtd->size >> this->bbt_erase_shift) - 1;
		dir = -1;
	} else {
		startblock = 0;
		dir = 1;
	}

	/* Do we have a bbt per chip? */
	if (td->options & NAND_BBT_PERCHIP) {
		chips = this->numchips;
		bbtblocks = this->chipsize >> this->bbt_erase_shift;
		startblock &= bbtblocks - 1;
	} else {
		chips = 1;
		bbtblocks = mtd->size >> this->bbt_erase_shift;
	}

    /* 分别遍历当前 mtd 设备下的 chips 个 nand */
	for (i = 0; i < chips; i++) {
		/* Reset version information */
		td->version[i] = 0;
		td->pages[i] = -1;
	
		/* Scan the maximum number of blocks */
		/* 从指定的位置开始，最多遍历 td->maxblocks 个存储块，来查找 bbt 数据 */
		for (block = 0; block < td->maxblocks; block++) {

			int actblock = startblock + dir * block;
			loff_t offs = (loff_t)actblock << this->bbt_erase_shift;

			/* Read first page */
			/* 从指定的 mtd 设备的指定偏移量位置处读取指定长度的数据到指定的缓冲区中 */
			scan_read(mtd, buf, offs, mtd->writesize, td);

			/* 判断指定的存储页缓冲区中是否包含指定的 bbt 描述符的 pattern 数据
               这个函数除了会判断 pattern 数据，还可以根据 bbt 描述符校验其他位置处的数据 */
			if (!check_pattern(buf, scanlen, mtd->writesize, td)) {
				td->pages[i] = actblock << blocktopage;
				if (td->options & NAND_BBT_VERSION) {
					offs = bbt_get_ver_offs(mtd, td);
					td->version[i] = buf[offs];
				}
				break;
			}
		}
		startblock += this->chipsize >> this->bbt_erase_shift;
	}
	
	/* Check, if we found a bbt for each requested chip */
	for (i = 0; i < chips; i++) {
		if (td->pages[i] == -1)
			pr_warn("Bad block table not found for chip %d\n", i);
		else
			pr_info("Bad block table found at page %d, version 0x%02X\n", td->pages[i],
				td->version[i]);
	}
	
	return 0;
}

/**
 * search_read_bbts - [GENERIC] scan the device for bad block table(s)
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @td: descriptor for the bad block table
 * @md: descriptor for the bad block table mirror
 *
 * Search and read the bad block table(s).
 */
/*********************************************************************************************************
** 函数名称: search_read_bbts
** 功能描述: 根据指定的 bbt 描述符从指定的 mtd 设备中遍历查找 bbt 数据，并在 td 中记录读取到的 bbt 信息 
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : td - 当前 nand 的主 bbt 描述符
**		   : md - 当前 nand 的镜像 bbt 描述符
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static void search_read_bbts(struct mtd_info *mtd, uint8_t *buf,
			     struct nand_bbt_descr *td,
			     struct nand_bbt_descr *md)
{
	/* Search the primary table */
	search_bbt(mtd, buf, td);

	/* Search the mirror table */
	if (md)
		search_bbt(mtd, buf, md);
}

/**
 * write_bbt - [GENERIC] (Re)write the bad block table
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @td: descriptor for the bad block table
 * @md: descriptor for the bad block table mirror
 * @chipsel: selector for a specific chip, -1 for all
 *
 * (Re)write the bad block table.
 */
/*********************************************************************************************************
** 函数名称: write_bbt
** 功能描述: 把指定的主 bbt 描述符中的 bbt 数据写入到指定的 mtd 设备用来存储 bbt 数据的存储块中
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : td - 当前 nand 的主 bbt 描述符
**		   : md - 当前 nand 的镜像 bbt 描述符
**		   : chipsel - 需要写入 bbt 的芯片索引，-1 表示所有芯片
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int write_bbt(struct mtd_info *mtd, uint8_t *buf,
		     struct nand_bbt_descr *td, struct nand_bbt_descr *md,
		     int chipsel)
{
	struct nand_chip *this = mtd->priv;
	struct erase_info einfo;
	int i, j, res, chip = 0;
	int bits, startblock, dir, page, offs, numblocks, sft, sftmsk;
	int nrchips, bbtoffs, pageoffs, ooboffs;
	uint8_t msk[4];
	uint8_t rcode = td->reserved_block_code;
	size_t retlen, len = 0;
	loff_t to;
	struct mtd_oob_ops ops;

	ops.ooblen = mtd->oobsize;
	ops.ooboffs = 0;
	ops.datbuf = NULL;
	ops.mode = MTD_OPS_PLACE_OOB;

	if (!rcode)
		rcode = 0xff;
	
	/* Write bad block table per chip rather than per device? */
	if (td->options & NAND_BBT_PERCHIP) {
		numblocks = (int)(this->chipsize >> this->bbt_erase_shift);
		/* Full device write or specific chip? */
		if (chipsel == -1) {
			nrchips = this->numchips;
		} else {
			nrchips = chipsel + 1;
			chip = chipsel;
		}
	} else {
		numblocks = (int)(mtd->size >> this->bbt_erase_shift);
		nrchips = 1;
	}

	/* Loop through the chips */
	for (; chip < nrchips; chip++) {
		/*
		 * There was already a version of the table, reuse the page
		 * This applies for absolute placement too, as we have the
		 * page nr. in td->pages.
		 */
		if (td->pages[chip] != -1) {
			page = td->pages[chip];
			goto write;
		}

		/*
		 * Automatic placement of the bad block table. Search direction
		 * top -> down?
		 */
		if (td->options & NAND_BBT_LASTBLOCK) {
			startblock = numblocks * (chip + 1) - 1;
			dir = -1;
		} else {
			startblock = chip * numblocks;
			dir = 1;
		}

        /* 尝试找到一个好的、空闲的存储块用来存储新的 bbt 数据 */
		for (i = 0; i < td->maxblocks; i++) {
			int block = startblock + dir * i;

			/* Check, if the block is bad */
			switch ((this->bbt[block >> 2] >>
				 (2 * (block & 0x03))) & 0x03) {
			case 0x01:
			case 0x03:
				continue;
			}
				 
			page = block <<
				(this->bbt_erase_shift - this->page_shift);
			/* Check, if the block is used by the mirror table */
			if (!md || md->pages[chip] != page)
				goto write;
		}
		pr_err("No space left to write bad block table\n");
		return -ENOSPC;
	write:

		/* Set up shift count and masks for the flash table */
		bits = td->options & NAND_BBT_NRBITS_MSK;
		msk[2] = ~rcode;
		switch (bits) {
		case 1: sft = 3; sftmsk = 0x07; msk[0] = 0x00; msk[1] = 0x01;
			msk[3] = 0x01;
			break;
		case 2: sft = 2; sftmsk = 0x06; msk[0] = 0x00; msk[1] = 0x01;
			msk[3] = 0x03;
			break;
		case 4: sft = 1; sftmsk = 0x04; msk[0] = 0x00; msk[1] = 0x0C;
			msk[3] = 0x0f;
			break;
		case 8: sft = 0; sftmsk = 0x00; msk[0] = 0x00; msk[1] = 0x0F;
			msk[3] = 0xff;
			break;
		default: return -EINVAL;
		}

		bbtoffs = chip * (numblocks >> 2);

		to = ((loff_t)page) << this->page_shift;

		/* Must we save the block contents? */
		if (td->options & NAND_BBT_SAVECONTENT) {
			/* Make it block aligned */
			to &= ~((loff_t)((1 << this->bbt_erase_shift) - 1));
			len = 1 << this->bbt_erase_shift;

            /* 把当前存储块中的所有存储数据读取到指定的缓冲区中 */
			res = mtd_read(mtd, to, len, &retlen, buf);
			if (res < 0) {
				if (retlen != len) {
					pr_info("nand_bbt: error reading block "
						"for writing the bad block table\n");
					return res;
				}
				pr_warn("nand_bbt: ECC error while reading "
					"block for writing bad block table\n");
			}
			
			/* Read oob data */
			ops.ooblen = (len >> this->page_shift) * mtd->oobsize;
			ops.oobbuf = &buf[len];
			
            /* 把当前存储块中的所有 OOB 数据读取到指定的缓冲区中（放在和存储数据相邻的位置处） */
			res = mtd_read_oob(mtd, to + mtd->writesize, &ops);
			if (res < 0 || ops.oobretlen != ops.ooblen)
				goto outerr;

			/* Calc the byte offset in the buffer */
			pageoffs = page - (int)(to >> this->page_shift);
			offs = pageoffs << this->page_shift;

			/* Preset the bbt area with 0xff */
            /* 把剩余的、没有数据的空闲空间数据设置为全 0xFF 状态 */
			memset(&buf[offs], 0xff, (size_t)(numblocks >> sft));
			ooboffs = len + (pageoffs * mtd->oobsize);

		} else if (td->options & NAND_BBT_NO_OOB) {
			ooboffs = 0;
			offs = td->len;
			/* The version byte */
			if (td->options & NAND_BBT_VERSION)
				offs++;
			/* Calc length */
			len = (size_t)(numblocks >> sft);
			len += offs;
			/* Make it page aligned! */
			len = ALIGN(len, mtd->writesize);
			/* Preset the buffer with 0xff */
			memset(buf, 0xff, len);
			/* Pattern is located at the begin of first page */
			memcpy(buf, td->pattern, td->len);
		} else {
			/* Calc length */
			len = (size_t)(numblocks >> sft);
			/* Make it page aligned! */
			len = ALIGN(len, mtd->writesize);
			/* Preset the buffer with 0xff */
			memset(buf, 0xff, len +
			       (len >> this->page_shift)* mtd->oobsize);
			offs = 0;
			ooboffs = len;
			/* Pattern is located in oob area of first page */
			memcpy(&buf[ooboffs + td->offs], td->pattern, td->len);
		}

		if (td->options & NAND_BBT_VERSION)
			buf[ooboffs + td->veroffs] = td->version[chip];

		/* Walk through the memory table */
		for (i = 0; i < numblocks;) {
			uint8_t dat;
			dat = this->bbt[bbtoffs + (i >> 2)];
			for (j = 0; j < 4; j++, i++) {
				int sftcnt = (i << (3 - sft)) & sftmsk;
				
				/* Do not store the reserved bbt blocks! */
                /* 根据当前内存中的 bbt 数据来初始化当前缓冲区中的 bbt 数据 */
			    buf[offs + (i >> sft)] &=
					~(msk[dat & 0x03] << sftcnt);
				dat >>= 2;
			}
		}

		memset(&einfo, 0, sizeof(einfo));
		einfo.mtd = mtd;
		einfo.addr = to;
		einfo.len = 1 << this->bbt_erase_shift;

		/* 根据指定的擦除操作信息擦除指定的 mtd 设备中指定的数据 */
		res = nand_erase_nand(mtd, &einfo, 1);
		if (res < 0)
			goto outerr;

		/* 把初始化好的 bbt 数据写入到指定的 mtd 设备的指定偏移量位置处 */
		res = scan_write_bbt(mtd, to, len, buf,
				td->options & NAND_BBT_NO_OOB ? NULL :
				&buf[len]);
		if (res < 0)
			goto outerr;

		pr_info("Bad block table written to 0x%012llx, version 0x%02X\n",
			 (unsigned long long)to, td->version[chip]);

		/* Mark it as used */
		td->pages[chip] = page;
	}
	
	return 0;

 outerr:
	pr_warn("nand_bbt: error while writing bad block table %d\n", res);
	return res;
}

/**
 * nand_memory_bbt - [GENERIC] create a memory based bad block table
 * @mtd: MTD device structure
 * @bd: descriptor for the good/bad block search pattern
 *
 * The function creates a memory based bbt by scanning the device for
 * manufacturer / software marked good / bad blocks.
 */
/*********************************************************************************************************
** 函数名称: nand_memory_bbt
** 功能描述: 根据指定的 bbt 描述符遍历指定的 mtd 设备存储块来创建内存中的 bbt 数据结构
** 输	 入: mtd - mtd 设备信息
**		   : bd - 当前 nand 的 bbt 描述符
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static inline int nand_memory_bbt(struct mtd_info *mtd, struct nand_bbt_descr *bd)
{
	struct nand_chip *this = mtd->priv;

	bd->options &= ~NAND_BBT_SCANEMPTY;

	/* 根据指定的 bbt 描述符遍历指定的 mtd 设备存储块来创建内存中的 bbt 数据结构 */
	return create_bbt(mtd, this->buffers->databuf, bd, -1);
}

/**
 * check_create - [GENERIC] create and write bbt(s) if necessary
 * @mtd: MTD device structure
 * @buf: temporary buffer
 * @bd: descriptor for the good/bad block search pattern
 *
 * The function checks the results of the previous call to read_bbt and creates
 * / updates the bbt(s) if necessary. Creation is necessary if no bbt was found
 * for the chip/device. Update is necessary if one of the tables is missing or
 * the version nr. of one table is less than the other.
 */
/*********************************************************************************************************
** 函数名称: check_create
** 功能描述: 根据指定的 bbt 描述符校验并更新指定的 mtd 设备 bbt 数据，如果之前没有 bbt 数据，则通过
**		   : 扫描 nand 设备来创建一个新的 bbt 并写入 nand 中
** 输	 入: mtd - mtd 设备信息
**		   : buf - 存储读取到的 bbt 数据缓冲区
**		   : bd - 当前 nand 的 bbt 描述符
** 输	 出: int - 操作状态，0 表示操作成功
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
static int check_create(struct mtd_info *mtd, uint8_t *buf, struct nand_bbt_descr *bd)
{
	int i, chips, writeops, create, chipsel, res, res2;
	struct nand_chip *this = mtd->priv;
	struct nand_bbt_descr *td = this->bbt_td;
	struct nand_bbt_descr *md = this->bbt_md;
	struct nand_bbt_descr *rd, *rd2;

	/* Do we have a bbt per chip? */
	if (td->options & NAND_BBT_PERCHIP)
		chips = this->numchips;
	else
		chips = 1;

	for (i = 0; i < chips; i++) {
		writeops = 0;
		create = 0;
		rd = NULL;
		rd2 = NULL;
		res = res2 = 0;
		/* Per chip or per device? */
		chipsel = (td->options & NAND_BBT_PERCHIP) ? i : -1;
		
		/* Mirrored table available? */
		if (md) {
			if (td->pages[i] == -1 && md->pages[i] == -1) {
				create = 1;
				writeops = 0x03;
			} else if (td->pages[i] == -1) {
				rd = md;
				writeops = 0x01;
			} else if (md->pages[i] == -1) {
				rd = td;
				writeops = 0x02;
			} else if (td->version[i] == md->version[i]) {
				rd = td;
				if (!(td->options & NAND_BBT_VERSION))
					rd2 = md;
			} else if (((int8_t)(td->version[i] - md->version[i])) > 0) {
				rd = td;
				writeops = 0x02;
			} else {
				rd = md;
				writeops = 0x01;
			}
		} else {
			if (td->pages[i] == -1) {
				create = 1;
				writeops = 0x01;
			} else {
				rd = td;
			}
		}

		/* 根据指定的 bbt 描述符遍历指定的 mtd 设备存储块来创建内存中的 bbt 数据结构 */
		if (create) {
			/* Create the bad block table by scanning the device? */
			if (!(td->options & NAND_BBT_CREATE))
				continue;

			/* Create the table in memory by scanning the chip(s) */
			if (!(this->bbt_options & NAND_BBT_CREATE_EMPTY))
				create_bbt(mtd, buf, bd, chipsel);

			td->version[i] = 1;
			if (md)
				md->version[i] = 1;
		}

		/* Read back first? */
		/* 根据 nand 中存储的 bbt 数据更新 ram 中的 bbt 数据 */
		if (rd) {
			res = read_abs_bbt(mtd, buf, rd, chipsel);
			if (mtd_is_eccerr(res)) {
				/* Mark table as invalid */
				rd->pages[i] = -1;
				rd->version[i] = 0;
				i--;
				continue;
			}
		}
		
		/* If they weren't versioned, read both */		
		/* 根据 nand 中存储的 bbt 数据更新 ram 中的 bbt 数据 */
		if (rd2) {
			res2 = read_abs_bbt(mtd, buf, rd2, chipsel);
			if (mtd_is_eccerr(res2)) {
				/* Mark table as invalid */
				rd2->pages[i] = -1;
				rd2->version[i] = 0;
				i--;
				continue;
			}
		}

		/* Scrub the flash table(s)? */
		if (mtd_is_bitflip(res) || mtd_is_bitflip(res2))
			writeops = 0x03;

		/* Update version numbers before writing */
		if (md) {
			td->version[i] = max(td->version[i], md->version[i]);
			md->version[i] = td->version[i];
		}

		/* Write the bad block table to the device? */
		/* 把主 bbt 描述符中的 bbt 数据写入到指定的 mtd 设备用来存储 bbt 数据的存储块中 */
		if ((writeops & 0x01) && (td->options & NAND_BBT_WRITE)) {
			res = write_bbt(mtd, buf, td, md, chipsel);
			if (res < 0)
				return res;
		}

		/* Write the mirror bad block table to the device? */		
		/* 把镜像 bbt 描述符中的 bbt 数据写入到指定的 mtd 设备用来存储 bbt 数据的存储块中 */
		if ((writeops & 0x02) && md && (md->options & NAND_BBT_WRITE)) {
			res = write_bbt(mtd, buf, md, td, chipsel);
			if (res < 0)
				return res;
		}
	}
	
	return 0;
}

/**
 * mark_bbt_regions - [GENERIC] mark the bad block table regions
 * @mtd: MTD device structure
 * @td: bad block table descriptor
 *
 * The bad block table regions are marked as "bad" to prevent accidental
 * erasures / writes. The regions are identified by the mark 0x02.
 */
static void mark_bbt_region(struct mtd_info *mtd, struct nand_bbt_descr *td)
{
	struct nand_chip *this = mtd->priv;
	int i, j, chips, block, nrblocks, update;
	uint8_t oldval, newval;

	/* Do we have a bbt per chip? */
	if (td->options & NAND_BBT_PERCHIP) {
		chips = this->numchips;
		nrblocks = (int)(this->chipsize >> this->bbt_erase_shift);
	} else {
		chips = 1;
		nrblocks = (int)(mtd->size >> this->bbt_erase_shift);
	}

	for (i = 0; i < chips; i++) {
		if ((td->options & NAND_BBT_ABSPAGE) ||
		    !(td->options & NAND_BBT_WRITE)) {
			if (td->pages[i] == -1)
				continue;
			block = td->pages[i] >> (this->bbt_erase_shift - this->page_shift);
			block <<= 1;
			oldval = this->bbt[(block >> 3)];
			newval = oldval | (0x2 << (block & 0x06));
			this->bbt[(block >> 3)] = newval;
			if ((oldval != newval) && td->reserved_block_code)
				nand_update_bbt(mtd, (loff_t)block << (this->bbt_erase_shift - 1));
			continue;
		}
		update = 0;
		if (td->options & NAND_BBT_LASTBLOCK)
			block = ((i + 1) * nrblocks) - td->maxblocks;
		else
			block = i * nrblocks;
		block <<= 1;
		for (j = 0; j < td->maxblocks; j++) {
			oldval = this->bbt[(block >> 3)];
			newval = oldval | (0x2 << (block & 0x06));
			this->bbt[(block >> 3)] = newval;
			if (oldval != newval)
				update = 1;
			block += 2;
		}
		/*
		 * If we want reserved blocks to be recorded to flash, and some
		 * new ones have been marked, then we need to update the stored
		 * bbts.  This should only happen once.
		 */
		if (update && td->reserved_block_code)
			nand_update_bbt(mtd, (loff_t)(block - 2) << (this->bbt_erase_shift - 1));
	}
}

/**
 * verify_bbt_descr - verify the bad block description
 * @mtd: MTD device structure
 * @bd: the table to verify
 *
 * This functions performs a few sanity checks on the bad block description
 * table.
 */
static void verify_bbt_descr(struct mtd_info *mtd, struct nand_bbt_descr *bd)
{
	struct nand_chip *this = mtd->priv;
	u32 pattern_len;
	u32 bits;
	u32 table_size;

	if (!bd)
		return;

	pattern_len = bd->len;
	bits = bd->options & NAND_BBT_NRBITS_MSK;

	BUG_ON((this->bbt_options & NAND_BBT_NO_OOB) &&
			!(this->bbt_options & NAND_BBT_USE_FLASH));
	BUG_ON(!bits);

	if (bd->options & NAND_BBT_VERSION)
		pattern_len++;

	if (bd->options & NAND_BBT_NO_OOB) {
		BUG_ON(!(this->bbt_options & NAND_BBT_USE_FLASH));
		BUG_ON(!(this->bbt_options & NAND_BBT_NO_OOB));
		BUG_ON(bd->offs);
		if (bd->options & NAND_BBT_VERSION)
			BUG_ON(bd->veroffs != bd->len);
		BUG_ON(bd->options & NAND_BBT_SAVECONTENT);
	}

	if (bd->options & NAND_BBT_PERCHIP)
		table_size = this->chipsize >> this->bbt_erase_shift;
	else
		table_size = mtd->size >> this->bbt_erase_shift;
	table_size >>= 3;
	table_size *= bits;
	if (bd->options & NAND_BBT_NO_OOB)
		table_size += pattern_len;
	BUG_ON(table_size > (1 << this->bbt_erase_shift));
}

/**
 * nand_scan_bbt - [NAND Interface] scan, find, read and maybe create bad block table(s)
 * @mtd: MTD device structure
 * @bd: descriptor for the good/bad block search pattern
 *
 * The function checks, if a bad block table(s) is/are already available. If
 * not it scans the device for manufacturer marked good / bad blocks and writes
 * the bad block table(s) to the selected place.
 *
 * The bad block table memory is allocated here. It must be freed by calling
 * the nand_free_bbt function.
 */
int nand_scan_bbt(struct mtd_info *mtd, struct nand_bbt_descr *bd)
{
	struct nand_chip *this = mtd->priv;
	int len, res = 0;
	uint8_t *buf;
	struct nand_bbt_descr *td = this->bbt_td;
	struct nand_bbt_descr *md = this->bbt_md;

	len = mtd->size >> (this->bbt_erase_shift + 2);
	/*
	 * Allocate memory (2bit per block) and clear the memory bad block
	 * table.
	 */
	this->bbt = kzalloc(len, GFP_KERNEL);
	if (!this->bbt)
		return -ENOMEM;

	/*
	 * If no primary table decriptor is given, scan the device to build a
	 * memory based bad block table.
	 */
	if (!td) {
		if ((res = nand_memory_bbt(mtd, bd))) {
			pr_err("nand_bbt: can't scan flash and build the RAM-based BBT\n");
			kfree(this->bbt);
			this->bbt = NULL;
		}
		return res;
	}
	verify_bbt_descr(mtd, td);
	verify_bbt_descr(mtd, md);

	/* Allocate a temporary buffer for one eraseblock incl. oob */
	len = (1 << this->bbt_erase_shift);
	len += (len >> this->page_shift) * mtd->oobsize;
	buf = vmalloc(len);
	if (!buf) {
		kfree(this->bbt);
		this->bbt = NULL;
		return -ENOMEM;
	}

	/* Is the bbt at a given page? */
	if (td->options & NAND_BBT_ABSPAGE) {
		read_abs_bbts(mtd, buf, td, md);
	} else {
		/* Search the bad block table using a pattern in oob */
		search_read_bbts(mtd, buf, td, md);
	}

	res = check_create(mtd, buf, bd);

	/* Prevent the bbt regions from erasing / writing */
	mark_bbt_region(mtd, td);
	if (md)
		mark_bbt_region(mtd, md);

	vfree(buf);
	return res;
}

/**
 * nand_update_bbt - [NAND Interface] update bad block table(s)
 * @mtd: MTD device structure
 * @offs: the offset of the newly marked block
 *
 * The function updates the bad block table(s).
 */
int nand_update_bbt(struct mtd_info *mtd, loff_t offs)
{
	struct nand_chip *this = mtd->priv;
	int len, res = 0;
	int chip, chipsel;
	uint8_t *buf;
	struct nand_bbt_descr *td = this->bbt_td;
	struct nand_bbt_descr *md = this->bbt_md;

	if (!this->bbt || !td)
		return -EINVAL;

	/* Allocate a temporary buffer for one eraseblock incl. oob */
	len = (1 << this->bbt_erase_shift);
	len += (len >> this->page_shift) * mtd->oobsize;
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Do we have a bbt per chip? */
	if (td->options & NAND_BBT_PERCHIP) {
		chip = (int)(offs >> this->chip_shift);
		chipsel = chip;
	} else {
		chip = 0;
		chipsel = -1;
	}

	td->version[chip]++;
	if (md)
		md->version[chip]++;

	/* Write the bad block table to the device? */
	if (td->options & NAND_BBT_WRITE) {
		res = write_bbt(mtd, buf, td, md, chipsel);
		if (res < 0)
			goto out;
	}
	/* Write the mirror bad block table to the device? */
	if (md && (md->options & NAND_BBT_WRITE)) {
		res = write_bbt(mtd, buf, md, td, chipsel);
	}

 out:
	kfree(buf);
	return res;
}

/*
 * Define some generic bad / good block scan pattern which are used
 * while scanning a device for factory marked good / bad blocks.
 */
static uint8_t scan_ff_pattern[] = { 0xff, 0xff };

static uint8_t scan_agand_pattern[] = { 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7 };

static struct nand_bbt_descr agand_flashbased = {
	.options = NAND_BBT_SCANEMPTY | NAND_BBT_SCANALLPAGES,
	.offs = 0x20,
	.len = 6,
	.pattern = scan_agand_pattern
};

/* Generic flash bbt descriptors */
static uint8_t bbt_pattern[] = {'B', 'b', 't', '0' };
static uint8_t mirror_pattern[] = {'1', 't', 'b', 'B' };

static struct nand_bbt_descr bbt_main_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP,
	.offs =	8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = NAND_BBT_SCAN_MAXBLOCKS,
	.pattern = bbt_pattern
};

static struct nand_bbt_descr bbt_mirror_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP,
	.offs =	8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = NAND_BBT_SCAN_MAXBLOCKS,
	.pattern = mirror_pattern
};

static struct nand_bbt_descr bbt_main_no_oob_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP
		| NAND_BBT_NO_OOB,
	.len = 4,
	.veroffs = 4,
	.maxblocks = NAND_BBT_SCAN_MAXBLOCKS,
	.pattern = bbt_pattern
};

static struct nand_bbt_descr bbt_mirror_no_oob_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP
		| NAND_BBT_NO_OOB,
	.len = 4,
	.veroffs = 4,
	.maxblocks = NAND_BBT_SCAN_MAXBLOCKS,
	.pattern = mirror_pattern
};

#define BADBLOCK_SCAN_MASK (~NAND_BBT_NO_OOB)
/**
 * nand_create_badblock_pattern - [INTERN] Creates a BBT descriptor structure
 * @this: NAND chip to create descriptor for
 *
 * This function allocates and initializes a nand_bbt_descr for BBM detection
 * based on the properties of @this. The new descriptor is stored in
 * this->badblock_pattern. Thus, this->badblock_pattern should be NULL when
 * passed to this function.
 */
static int nand_create_badblock_pattern(struct nand_chip *this)
{
	struct nand_bbt_descr *bd;
	if (this->badblock_pattern) {
		pr_warn("Bad block pattern already allocated; not replacing\n");
		return -EINVAL;
	}
	bd = kzalloc(sizeof(*bd), GFP_KERNEL);
	if (!bd)
		return -ENOMEM;
	bd->options = this->bbt_options & BADBLOCK_SCAN_MASK;
	bd->offs = this->badblockpos;
	bd->len = (this->options & NAND_BUSWIDTH_16) ? 2 : 1;
	bd->pattern = scan_ff_pattern;
	bd->options |= NAND_BBT_DYNAMICSTRUCT;
	this->badblock_pattern = bd;
	return 0;
}

/**
 * nand_default_bbt - [NAND Interface] Select a default bad block table for the device
 * @mtd: MTD device structure
 *
 * This function selects the default bad block table support for the device and
 * calls the nand_scan_bbt function.
 */
int nand_default_bbt(struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;

	/*
	 * Default for AG-AND. We must use a flash based bad block table as the
	 * devices have factory marked _good_ blocks. Erasing those blocks
	 * leads to loss of the good / bad information, so we _must_ store this
	 * information in a good / bad table during startup.
	 */
	if (this->options & NAND_IS_AND) {
		/* Use the default pattern descriptors */
		if (!this->bbt_td) {
			this->bbt_td = &bbt_main_descr;
			this->bbt_md = &bbt_mirror_descr;
		}
		this->bbt_options |= NAND_BBT_USE_FLASH;
		return nand_scan_bbt(mtd, &agand_flashbased);
	}

	/* Is a flash based bad block table requested? */
	if (this->bbt_options & NAND_BBT_USE_FLASH) {
		/* Use the default pattern descriptors */
		if (!this->bbt_td) {
			if (this->bbt_options & NAND_BBT_NO_OOB) {
				this->bbt_td = &bbt_main_no_oob_descr;
				this->bbt_md = &bbt_mirror_no_oob_descr;
			} else {
				this->bbt_td = &bbt_main_descr;
				this->bbt_md = &bbt_mirror_descr;
			}
		}
	} else {
		this->bbt_td = NULL;
		this->bbt_md = NULL;
	}

	if (!this->badblock_pattern)
		nand_create_badblock_pattern(this);

	return nand_scan_bbt(mtd, this->badblock_pattern);
}

/**
 * nand_isbad_bbt - [NAND Interface] Check if a block is bad
 * @mtd: MTD device structure
 * @offs: offset in the device
 * @allowbbt: allow access to bad block table region
 */
/*********************************************************************************************************
** 函数名称: nand_isbad_bbt
** 功能描述: 通过读取指定 mtd 设备的 bbt 数据判断指定偏移量位置的数据块是否是坏块
** 输	 入: mtd - mtd 设备信息
**         : ofs - 指定数据块的偏移量（全局偏移量）
**         : allowbbt - 表示是否允许访问 bbt 数据
** 输	 出: 0 - 不是坏块
**         : 1 - 是坏块
** 全局变量:
** 调用模块: 
*********************************************************************************************************/
int nand_isbad_bbt(struct mtd_info *mtd, loff_t offs, int allowbbt)
{
	struct nand_chip *this = mtd->priv;
	int block;
	uint8_t res;

	/* Get block number * 2 */
	block = (int)(offs >> (this->bbt_erase_shift - 1));
	res = (this->bbt[block >> 3] >> (block & 0x06)) & 0x03;

	MTDDEBUG(MTD_DEBUG_LEVEL2, "nand_isbad_bbt(): bbt info for offs 0x%08x: (block %d) 0x%02x\n",
	      (unsigned int)offs, block >> 1, res);

	switch ((int)res) {
	case 0x00:
		return 0;
	case 0x01:
		return 1;
	case 0x02:
		return allowbbt ? 0 : 1;
	}
	return 1;
}
