/*
 * Copyright (c) 2013      Sagar Trehan
 * Copyright (c) 2013-2014 Vasily Tarasov
 * Copyright (c) 2013-2014 Philip Shilane
 * Copyright (c) 2013-2014 Erez Zadok
 * Copyright (c) 2013-2014 Geoff Kuenning
 * Copyright (c) 2013-2014 Stony Brook University
 * Copyright (c) 2013-2014 Harvey Mudd College
 * Copyright (c) 2013-2014 The Research Foundation of the State University of New York
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 */

#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE /* important to keep right basename() version */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <openssl/des.h>
#include <ctype.h>

#include "libhashfile.h"
#include "liblog.h"

/* DES encryption routine encrypts or decrypts a single 8-byte DES_cblock */
#define DES_BLOCK_SIZE 8

/* Should be multiple of DES_BLOCK_SIZE, to ensure decryption */
#define PATH_TRUNCATE_SIZE (2 * DES_BLOCK_SIZE)

static DES_cblock des_key;
static DES_key_schedule keysched;
static char *progname;
static uint64_t files_processed;
static char *hashfile_name;
static char *out_filename;
static char *padding;
static int mode = DES_ENCRYPT;

/* result should be as large as data */
static void encrypt_block(char *data, int data_size, char *result)
{
	char in[DES_BLOCK_SIZE], out[DES_BLOCK_SIZE];
	int i, j;

	for (i = 0; i < (data_size - DES_BLOCK_SIZE + 1); i += DES_BLOCK_SIZE) {
		memcpy(in, (data + i), DES_BLOCK_SIZE);
		DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out,
						&keysched, mode);
		memcpy((result + i), out, DES_BLOCK_SIZE);
	}

	if (i != data_size) {
		if (DES_BLOCK_SIZE > PATH_TRUNCATE_SIZE) {
			for (j = 0; j < DES_BLOCK_SIZE - PATH_TRUNCATE_SIZE + 1;
					j += PATH_TRUNCATE_SIZE) {
				memcpy(in + j, padding, PATH_TRUNCATE_SIZE);
			}
			memcpy(in + j, padding, DES_BLOCK_SIZE - j);
		} else
			memcpy(in, padding, DES_BLOCK_SIZE);

		memcpy(in, (data + i), data_size - i);
		DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out,
						&keysched, mode);
		memcpy((result + i), out, data_size - i);
	}

	return;
}

static void add_chunks_to_file(struct hashfile_handle *out_handle,
				struct hashfile_handle *handle)
{
	const struct chunk_info *ci;
	struct chunk_info eci;
	int32_t hash_size;
	char *eblk;

	hash_size = hashfile_hash_size(handle) / 8;

	eblk = (char *)malloc(sizeof(char) * hash_size);
	if (!eblk)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory "
				"for encrypted chunk hash!");

	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		encrypt_block((char *)ci->hash, hash_size, eblk);

		eci = *ci;
		eci.hash = (uint8_t *)eblk;

		hashfile_add_chunk(out_handle, &eci);
	}

	free(eblk);

	return;
}

/*
 * Ensures the following for every file type:
 *
 * a) All characters in file type should either be
 *    digit or alphabet.
 *
 * b) File type should have at least one alpha symbol..
 *
 * c) Size of file type should not be greater then 4 symbols.
 *
 * This will help us avoid temporary files like ~1~, 001
 * and misleading extension like txt.default, this should
 * return .txt as extension instead of .default.
 *
 * Return: 0 on success.
 */
static int _check_file_type(char *ftype)
{
	int i = 0;
	uint8_t alpha = 0;

	while (*(ftype + i) != '\0') {
		if (!isalnum(*(ftype + i)))
			return 1;

		if (isalpha(*(ftype + i)))
			alpha = 1;

		i++;
	}

	if (!alpha || i > 4)
		return 1;

	return 0;
}

static char *get_file_type(const char *path)
{
	char ftype[MAX_PATH_SIZE], *type = NULL;
	int extlen;
	int l;

	l = strlen(path);

	do {
		extlen = 0;
		l--;

		while (l >= 0 && path[l] != '/' && path[l] != '.') {
			l--;
			extlen++;
		}

		if (l < 0 || path[l] == '/') {
			l = strlen(path);
			break;
		} else
			snprintf(ftype, extlen + 1, "%s", (path + l + 1));

	} while (_check_file_type(ftype));

	type = (char *)malloc(sizeof(char) * (strlen(path) - l + 1));
	if (!type)
		liblog_logen(LOG_FTL, errno,
			"Error while allocating memory!");
	snprintf(type, (strlen(path) - l + 1), "%s", path + l);

	return type;
}

static void prepare_out_hashfile_name(void)
{
	int len;

	if (out_filename)
		return;

	len = strlen(hashfile_name);

	/* +8 because of ".deanon" string which we will add. */
	out_filename = (char *)malloc(sizeof(char) * (len + 8));
	if (!out_filename)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory "
				"for output file name!");

	if (mode == DES_ENCRYPT)
		sprintf(out_filename, "%s.anon", hashfile_name);
	else
		sprintf(out_filename, "%s.deanon", hashfile_name);

	return;
}

static int hexstring_to_hexnum(char *inp, int len, char *result)
{
	int i = 0, j = 0;
	char ch = 0;

	for (i = 0; i < len; i += 1) {
		if (i & 1)
			ch = ch << 4;

		if (*(inp + i) >= '0' && *(inp + i) <= '9')
			ch |= (*(inp + i) - '0');
		else if (*(inp + i) >= 'a' && *(inp + i) <= 'f')
			ch |= ((*(inp + i) - 'a') + 10);
		else if (*(inp + i) >= 'A' && *(inp + i) <= 'F')
			ch |= ((*(inp + i) - 'A') + 10);

		if (i & 1) {
			*(result + j++) = ch;
			ch = 0;
		}
	}

	return j;
}

/*
 * Encrypts input string and returns the result in a malloced region.
 * The caller is responsible for freeing the memory later.
 * Both input and return strings are '\0' terminated.
 */
static char *encrypt_path_component(char *inp)
{
	char *in = NULL, *result = NULL;
	unsigned char *out = NULL;
	int i = 0, len;

	assert(inp);
	assert(padding);

	len = strlen(inp);

	in = (char *)malloc(sizeof(char) *
		(len < PATH_TRUNCATE_SIZE ? PATH_TRUNCATE_SIZE : len) + 1);
	if (!in)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory!");

	result = (char *)malloc(sizeof(char) * PATH_TRUNCATE_SIZE + 1);
	if (!result)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory!");

	if (mode == DES_DECRYPT)
		len = hexstring_to_hexnum(inp, len, in);
	else
		snprintf(in, len + 1, "%s", inp);

	/* Append component to make it as large as the TRUNCATE_SIZE */
	while (len < PATH_TRUNCATE_SIZE)
		in[len++] = padding[i++];

	out = (unsigned char *)malloc(sizeof(char) * len);
	if (!out)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory!");

	encrypt_block(in, PATH_TRUNCATE_SIZE, (char *)out);

	if (mode == DES_DECRYPT) {
		snprintf(result, PATH_TRUNCATE_SIZE / 2 + 1, "%s", out);
		snprintf(result + PATH_TRUNCATE_SIZE / 2,
			PATH_TRUNCATE_SIZE / 2 + 1, "%s", padding);
	} else {
		for (i = 0; i < (PATH_TRUNCATE_SIZE / 2); i += 1)
			snprintf((result + 2 * i), 3, "%02x", out[i]);
	}

	free(in);
	free(out);

	return result;
}

static int encrypt_path(const char *path, char *result, int rsize)
{
	int plen;
	int rlen;
	char *inpath;
	char *token;
	char *ftype;
	char *ecomp;

	plen = strlen(path);
	rlen = 0;

	memset(result, 0, rsize);

	if (path[0] == '/') {
		result[0] = '/';
		rlen++;
	}

	inpath = (char *)malloc(sizeof(char) * plen + 1);
	if (!inpath)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory!");

	ftype = get_file_type(path);
	snprintf(inpath, plen - strlen(ftype) + 1, "%s", path);

	token = strtok(inpath, "/");
	while (token) {
		ecomp = encrypt_path_component(token);
		assert((rlen + strlen(ecomp) + 1) < rsize);
		snprintf(result + rlen, strlen(ecomp) + 1, "%s", ecomp);
		rlen += strlen(ecomp);
		assert((rlen + 1) < rsize);
		result[rlen++] = '/';
		token = strtok(NULL, "/");
		free(ecomp);
	}

	rlen--;

	/* Add file type */
	assert((rlen + strlen(ftype) + 1) < rsize);
	snprintf(result + rlen, strlen(ftype) + 1, "%s", ftype);

	free(inpath);
	free(ftype);

	return rlen;
}

static struct hashfile_handle *get_output_handle(struct hashfile_handle *handle,
								char *out_name)
{
	struct hashfile_handle *out_handle;
	struct fixed_chnking_params fxd_params;
	struct var_chnking_params var_params;
	enum hshing_method hmeth;
	enum chnking_method cmeth;
	int32_t hash_size;
	const char *root_path;
	char *root_epath;
	int ret;

	cmeth = hashfile_chunking_method(handle);
	hmeth = hashfile_hashing_method(handle);
	hash_size = hashfile_hash_size(handle);
	root_path = hashfile_rootpath(handle);

	root_epath = (char *)malloc(sizeof(char) * MAX_PATH_SIZE);
	if (!root_epath)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory "
					"for encrypted root path!");

	ret = encrypt_path(root_path, root_epath, MAX_PATH_SIZE);
	if (ret < 0)
		liblog_sloge(LOG_FTL, "Error while encrypting root path!");

	out_handle = hashfile_open4write(out_name, cmeth, hmeth,
						hash_size, root_epath);
	if (!out_handle)
		liblog_logen(LOG_FTL, errno, "Can't open %s", out_name);

	if (cmeth == FIXED) {
		ret = hashfile_fxd_chunking_params(handle, &fxd_params);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while getting hash file parameters!");

		ret = hashfile_set_fxd_chnking_params(out_handle, &fxd_params);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while setting hash file parameters!");

	} else if (cmeth == VARIABLE) {
		ret = hashfile_var_chunking_params(handle, &var_params);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while getting hash file parameters!");

		ret = hashfile_set_var_chnking_params(out_handle, &var_params);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while setting hash file parameters!");

	} else
		assert(0);

	free(root_epath);

	return out_handle;
}

static void process_hashfile(void)
{
	struct hashfile_handle *out_handle;
	struct hashfile_handle *handle;
	struct stat stat_buf;
	char *epath, *elink, *link;
	int ret;

	liblog_slog(LOG_INF, "Processing: %s", hashfile_name);

	handle = hashfile_open(hashfile_name);
	if (!handle)
		liblog_logen(LOG_FTL, errno, "Can't open %s", hashfile_name);

	prepare_out_hashfile_name();
	liblog_slog(LOG_INF, "Output file name: %s", out_filename);

	out_handle = get_output_handle(handle, out_filename);
	if (!out_handle)
		liblog_logen(LOG_FTL, errno,
				"Error while opening output hash file!");

	epath = (char *)malloc(sizeof(char) * MAX_PATH_SIZE);
	if (!epath)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory "
						"for encrypted path!");

	elink = (char *)malloc(sizeof(char) * MAX_PATH_SIZE);
	if (!elink)
		liblog_logen(LOG_FTL, errno, "Error while allocating memory!"
						"for encrypted target path!");

	/* iterating over the files */
	while (1) {
		ret = hashfile_next_file(handle);
		if (ret == 0)
			break;
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while processing hashfile!");

		memset(&stat_buf, 0, sizeof(stat_buf));

		stat_buf.st_size = hashfile_curfile_size(handle);
		stat_buf.st_blocks = hashfile_curfile_blocks(handle);
		stat_buf.st_uid = hashfile_curfile_uid(handle);
		stat_buf.st_gid = hashfile_curfile_gid(handle);
		stat_buf.st_mode = hashfile_curfile_perm(handle);
		stat_buf.st_atime = hashfile_curfile_atime(handle);
		stat_buf.st_mtime = hashfile_curfile_mtime(handle);
		stat_buf.st_ctime = hashfile_curfile_ctime(handle);
		stat_buf.st_nlink = hashfile_curfile_hardlinks(handle);
		stat_buf.st_dev = hashfile_curfile_deviceid(handle);
		stat_buf.st_ino = hashfile_curfile_inodenum(handle);

		ret = encrypt_path(hashfile_curfile_path(handle),
							epath, MAX_PATH_SIZE);
		if (ret < 0)
			liblog_sloge(LOG_FTL,
				"Error while encrypting file path!");

		link = hashfile_curfile_linkpath(handle);
		if (link) {
			ret = encrypt_path(link, elink, MAX_PATH_SIZE);
			if (ret < 0)
				liblog_sloge(LOG_FTL, "Error while "
					"encrypting link path of a file!");
		}

		ret = hashfile_add_file(out_handle, epath, &stat_buf,
					(link ? elink : NULL));
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while adding a file!");

		add_chunks_to_file(out_handle, handle);

		files_processed++;
	}

	liblog_slog(LOG_INF, "%"PRIu64" files processed", files_processed);

	hashfile_close(handle);
	hashfile_close(out_handle);

	free(epath);
	free(elink);

	return;
}

static void usage()
{
	printf("Usage: ");
	printf("%s -k <encryption_key> [-o <output_file>] ", progname);
	printf("[-p <padding>] [-d] ");
	printf("<input_file_path>\n");
	printf("Options:\n");
	printf("  -k: Key to use for encryption\n");
	printf("  -o: Name of the output file. Default: <input_file>.anon\n");
	printf("  -p: Padding content to use for encryption. "
		"Should contain %d symbols. Default: string of '0' symbols\n",
		PATH_TRUNCATE_SIZE);
	printf("  -d: If specifed, program performs decryption instead of encryption\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int ret = 0;
	char *encrypt_key = NULL;

	/* Save program name */
	progname = argv[0];

	/* Collecting command line parameters */
	while (1) {
		opt = getopt(argc, argv, "hk:o:p:d");
		if (opt == -1)
			break;

		switch (opt) {
		case 'k':
			encrypt_key = optarg;
			break;
		case 'o':
			out_filename = optarg;
			break;
		case 'd':
			mode = DES_DECRYPT;
			break;
		case 'p':
			padding = optarg;
			break;
		case 'h':
			usage();
			return 0;
		case '?':
			liblog_slog(LOG_FTL, "Wrong usage!");
			usage();
			return -1;
		}
	}

	if (!encrypt_key) {
		liblog_slog(LOG_FTL, "Encryption key is not specified!");
		usage();
		return -1;
	}

	if ((argc - optind) > 1) {
		liblog_slog(LOG_FTL,
			"Should specify only one input file!\n");
		usage();
		return -1;
	}

	if (optind == argc) {
		liblog_slog(LOG_FTL, "No input files specified!");
		usage();
		return -1;
	}

	if (padding) {
		if ((strlen(padding) != PATH_TRUNCATE_SIZE)) {
			liblog_slog(LOG_FTL, "Padding should be %d"
			" symbols long.", PATH_TRUNCATE_SIZE);
			usage();
			return -1;
		}
	} else {
		padding = (char *)malloc(sizeof(char) * PATH_TRUNCATE_SIZE);
		if (!padding)
			liblog_sloge(LOG_FTL,
				"Error while allocating memory for padding");
		memset(padding, '0', PATH_TRUNCATE_SIZE);
	}

	DES_string_to_key(encrypt_key, &des_key);
	DES_set_key(&des_key, &keysched);

	/* Process input hash file */
	hashfile_name = argv[optind];
	process_hashfile();

	return ret;
}
