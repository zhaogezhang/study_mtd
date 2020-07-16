/*
 *  linux/include/linux/mtd/bbm.h
 *
 *  NAND family Bad Block Management (BBM) header file
 *    - Bad Block Table (BBT) implementation
 *
 *  Copyright (c) 2005-2007 Samsung Electronics
 *  Kyungmin Park <kyungmin.park@samsung.com>
 *
 *  Copyright (c) 2000-2005
 *  Thomas Gleixner <tglx@linuxtronix.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef __LINUX_MTD_BBM_H
#define __LINUX_MTD_BBM_H

/* The maximum number of NAND chips in an array */
#ifndef CONFIG_SYS_NAND_MAX_CHIPS
#define CONFIG_SYS_NAND_MAX_CHIPS	1
#endif

/**
 * struct nand_bbt_descr - bad block table descriptor
 * @param options	options for this descriptor
 * @param pages		the page(s) where we find the bbt, used with
 *			option BBT_ABSPAGE when bbt is searched,
 *			then we store the found bbts pages here.
 *			Its an array and supports up to 8 chips now
 * @param offs		offset of the pattern in the oob area of the page
 * @param veroffs	offset of the bbt version counter in the oob are of the page
 * @param version	version read from the bbt page during scan
 * @param len		length of the pattern, if 0 no pattern check is performed
 * @param maxblocks	maximum number of blocks to search for a bbt. This number of
 *			blocks is reserved at the end of the device
 *			where the tables are written.
 * @param reserved_block_code	if non-0, this pattern denotes a reserved
 *			(rather than bad) block in the stored bbt
 * @param pattern	pattern to identify bad block table or factory marked
 *			good / bad blocks, can be NULL, if len = 0
 *
 * Descriptor for the bad block table marker and the descriptor for the
 * pattern which identifies good and bad blocks. The assumption is made
 * that the pattern and the version count are always located in the oob area
 * of the first block.
 */
struct nand_bbt_descr {
	int options;      /* 表示当前 bbt 描述符的选项标志数据 */
	int pages[CONFIG_SYS_NAND_MAX_CHIPS];   /* 表示当前 bbt 描述符是从哪个 nand 存储页中读取出来的 */
	int offs;         /* 表示当前数据页的 OOB 区中存储的 pattern 数据在 OOB 区中的偏移量 */
	int veroffs;      /* 表示当前数据块的 bbt 版本计数在当前数据页的 OOB 中的偏移量 */
	uint8_t version[CONFIG_SYS_NAND_MAX_CHIPS];  /* 在 bbt 扫描期间从 bbt 页中读出的版本号信息 */
	int len;          /* 当前 bbt 描述符包含的 pattern 数据长度，0 表示不作 pattern 检查 */
	int maxblocks;    /* MTD 在查找 bbt 的时候，不会查找 NAND 芯片中所有的 block，而是最多查找 maxblocks 个 block */
	int reserved_block_code;  /* 表示当前 bbt 描述符保留的标记码，也就是在坏块扫描到时候，如果扫描到这个标志数据，则不认为是坏块 */
	uint8_t *pattern; /* 在扫描 nand 中的 bbt 数据的时候，用来做名字匹配的，如果匹配成功，则表示找到了想要的 bbt 数据 */
};

/* Options for the bad block table descriptors */

/* The number of bits used per block in the bbt on the device */
#define NAND_BBT_NRBITS_MSK	0x0000000F
#define NAND_BBT_1BIT		0x00000001
#define NAND_BBT_2BIT		0x00000002
#define NAND_BBT_4BIT		0x00000004
#define NAND_BBT_8BIT		0x00000008

/* The bad block table is in the last good block of the device */
/* 表示当前 nand flash 的 bbt 数据存储在最后一个好的数据块中，所以扫描 bbt 数据的时候需要从后往前扫描 */
#define NAND_BBT_LASTBLOCK	0x00000010

/* The bbt is at the given page, else we must scan for the bbt */
#define NAND_BBT_ABSPAGE	0x00000020

/* bbt is stored per chip on multichip devices */
/* 表示每个 nand 存储器的 bbt 数据都存储在各自的存储空间中 */
#define NAND_BBT_PERCHIP	0x00000080

/* bbt has a version counter at offset veroffs */
/* 表示当前 bbt 描述符是否包含 bbt 版本号，版本号占用一个字节空间 */
#define NAND_BBT_VERSION	0x00000100

/* Create a bbt if none exists */
#define NAND_BBT_CREATE		0x00000200
/*
 * Create an empty BBT with no vendor information. Vendor's information may be
 * unavailable, for example, if the NAND controller has a different data and OOB
 * layout or if this information is already purged. Must be used in conjunction
 * with NAND_BBT_CREATE.
 */
#define NAND_BBT_CREATE_EMPTY	0x00000400

/* Search good / bad pattern through all pages of a block */
/* 表示在扫描坏块的时候，会遍历一个数据块中的所有存储页 */
#define NAND_BBT_SCANALLPAGES	0x00000800

/* Scan block empty during good / bad block scan */
/* 表示在扫描 bbt 数据的时候，同时校验当前存储页中，除了 bbt 的 pattern 数据外，其他位置是否为全 0xFF
 * 如果开启了这个选项，会因为需要额外校验大量数据导致耗时变长 */
#define NAND_BBT_SCANEMPTY	0x00001000

/* Write bbt if neccecary */
/* 表示是否允许向 nand 中写入 bbt 数据 */
#define NAND_BBT_WRITE		0x00002000

/* Read and write back block contents when writing bbt */
#define NAND_BBT_SAVECONTENT	0x00004000

/* Search good / bad pattern on the first and the second page */
/* 表示在扫描坏块的时候，只遍历数据块的前两个数据页 */
#define NAND_BBT_SCAN2NDPAGE	0x00008000

/* Search good / bad pattern on the last page of the eraseblock */
/* 表示在扫描坏块的时候，只遍历数据块的最后一个数据页 */
#define NAND_BBT_SCANLASTPAGE	0x00010000

/*
 * Use a flash based bad block table. By default, OOB identifier is saved in
 * OOB area. This option is passed to the default bad block table function.
 */
/* 表示在 nand flash 中可能已经存储了 bbt 数据，我们在创建内存中的 bbt 数据时使用 nand 中的 bbt 数据 */
#define NAND_BBT_USE_FLASH	0x00020000

/*
 * Do not store flash based bad block table marker in the OOB area; store it
 * in-band.
 */
/* 表示 bbt pattern 不存储在 OOB 中，而是通过 inband 方式存储在存储页的数据存储区中 */
#define NAND_BBT_NO_OOB		0x00040000

/*
 * Do not write new bad block markers to OOB; useful, e.g., when ECC covers
 * entire spare area. Must be used with NAND_BBT_USE_FLASH.
 */
#define NAND_BBT_NO_OOB_BBM	0x00080000

/*
 * Flag set by nand_create_default_bbt_descr(), marking that the nand_bbt_descr
 * was allocated dynamicaly and must be freed in nand_release(). Has no meaning
 * in nand_chip.bbt_options.
 */
#define NAND_BBT_DYNAMICSTRUCT	0x80000000

/* The maximum number of blocks to scan for a bbt */
#define NAND_BBT_SCAN_MAXBLOCKS	4

/*
 * Constants for oob configuration
 */
#define ONENAND_BADBLOCK_POS	0

/*
 * Bad block scanning errors
 */
#define ONENAND_BBT_READ_ERROR          1
#define ONENAND_BBT_READ_ECC_ERROR      2
#define ONENAND_BBT_READ_FATAL_ERROR    4

/**
 * struct bbt_info - [GENERIC] Bad Block Table data structure
 * @param bbt_erase_shift	[INTERN] number of address bits in a bbt entry
 * @param badblockpos		[INTERN] position of the bad block marker in the oob area
 * @param bbt			[INTERN] bad block table pointer
 * @param badblock_pattern	[REPLACEABLE] bad block scan pattern used for initial bad block scan
 * @param priv			[OPTIONAL] pointer to private bbm date
 */
struct bbm_info {
	int bbt_erase_shift;
	int badblockpos;
	int options;

	uint8_t *bbt;

	int (*isbad_bbt) (struct mtd_info * mtd, loff_t ofs, int allowbbt);

	/* TODO Add more NAND specific fileds */
	struct nand_bbt_descr *badblock_pattern;

	void *priv;
};

/* OneNAND BBT interface */
extern int onenand_scan_bbt (struct mtd_info *mtd, struct nand_bbt_descr *bd);
extern int onenand_default_bbt (struct mtd_info *mtd);

#endif				/* __LINUX_MTD_BBM_H */
