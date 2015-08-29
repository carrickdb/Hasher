/*
 * Copyright (c) 2011-2014 Vasily Tarasov
 * Copyright (c) 2011      Will Buik
 * Copyright (c) 2011-2014 Philip Shilane
 * Copyright (c) 2011-2014 Erez Zadok
 * Copyright (c) 2011-2014 Geoff Kuenning
 * Copyright (c) 2011-2014 Stony Brook University
 * Copyright (c) 2011-2014 Harvey Mudd College
 * Copyright (c) 2011-2014 The Research Foundation of the State University of New York
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 */

#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <time.h>
#include <errno.h>

#define MAXLINE	4096

#include "libhashfile.h"
#include "liblog.h"

static char *progname;
static int show_file_info_only;
static int show_chunk_hashes;
static int show_file_hashes;
static int show_totals;

uint64_t total_files;
uint64_t total_bytes;
uint64_t total_chunks;

/* hash_size is the size of the hash in bytes */
static void print_chunk_info(const uint8_t *hash,
		 int hash_size, uint64_t chunk_size, uint8_t cratio)
{
	int j;

	printf("%.2hhx", hash[0]);
	for (j = 1; j < hash_size; j++)
		printf(":%.2hhx", hash[j]);

	printf("\t\t%" PRIu64 " ", chunk_size);
	printf("\t\t\t%" PRIu8 " ", cratio);
	printf("\n");
}

static void print_hashfile_header(struct hashfile_handle *handle)
{
	char buf[MAXLINE];
	time_t start_time;
	time_t end_time;
	time_t run_time;
	int ret;

	printf("Hash file version: %d\n", hashfile_version(handle));
	printf("Root path: %s\n", hashfile_rootpath(handle));
	printf("System id: %s\n", hashfile_sysid(handle) ?
			hashfile_sysid(handle) : "<not supported>");

	start_time = hashfile_start_time(handle);
	printf("Start time: %s", start_time ?
		ctime(&start_time) : "<not supported>\n");
	end_time = hashfile_end_time(handle);
	printf("End time: %s", end_time ?
		ctime(&end_time) : "<not supported>\n");
	run_time = end_time - start_time;
	printf("Total time: %d seconds\n",
		start_time * end_time ? (int)run_time : 0);

	printf("Files hashed: %" PRIu64 "\n", hashfile_numfiles(handle));
	printf("Chunks hashed: %" PRIu64 "\n", hashfile_numchunks(handle));
	printf("Bytes hashed: %" PRIu64 "\n", hashfile_numbytes(handle));

	ret = hashfile_chunking_method_str(handle, buf, MAXLINE);
	if (ret < 0)
		printf("Chunking method not recognized.\n");
	else
		printf("Chunking method: %s", buf);

	ret = hashfile_hashing_method_str(handle, buf, MAXLINE);
	if (ret < 0)
		printf("Hashing method not recognized.\n");
	else
		printf("Hashing method: %s", buf);
}

static void update_total_stats(struct hashfile_handle *handle)
{
	total_files += hashfile_numfiles(handle);
	total_bytes += hashfile_numbytes(handle);
	total_chunks += hashfile_numchunks(handle);
}

static void print_current_fileinfo(struct hashfile_handle *handle)
{
	uint64_t size, size_kb;
	time_t atm, mtm, ctm;
	char *target_path;

	printf("File path: %s\n", hashfile_curfile_path(handle));
	size = hashfile_curfile_size(handle);
	size_kb = size / 1024;
	printf("File size: %"PRIu64 "%s\n", (size_kb > 0) ? size_kb : size,
						(size_kb > 0) ? "KB" : "B");
	printf("512B file system blocks allocated: %"PRIu64"\n",
				hashfile_curfile_blocks(handle));

	printf("Chunks: %" PRIu64 "\n",
				 hashfile_curfile_numchunks(handle));

	/*
	 * Print extended statistics if they are available.
	 * Might be missing for some old hashfiles.
 	 */
	printf("UID: %"PRIu32"\n", hashfile_curfile_uid(handle));
	printf("GID: %"PRIu32"\n", hashfile_curfile_gid(handle));
	printf("Permission bits: %"PRIo64"\n", hashfile_curfile_perm(handle));

	atm = hashfile_curfile_atime(handle);
	mtm = hashfile_curfile_mtime(handle);
	ctm = hashfile_curfile_ctime(handle);
	printf("Access time: %s", ctime(&atm));
	printf("Modification time: %s", ctime(&mtm));
	printf("Change time: %s", ctime(&ctm));

	printf("Hardlinks: %"PRIu64"\n", hashfile_curfile_hardlinks(handle));
	printf("Device ID: %"PRIu64"\n", hashfile_curfile_deviceid(handle));
	printf("Inode Num: %"PRIu64"\n", hashfile_curfile_inodenum(handle));

	target_path = hashfile_curfile_linkpath(handle);
	if (target_path)
		printf("Target Path: %s\n", target_path);
}

static void update_whole_file_hash(uint8_t *hash,
			uint32_t hash_size, uint8_t *xored)
{
	int i;

	for (i = 0; i < hash_size; i++)
		xored[i] = xored[i] ^ hash[i];
}

static void display_chunk_hashes(struct hashfile_handle *handle,
					uint8_t *whole_file_hash)
{
	const struct chunk_info *ci;
	int hash_size;
	static int first_entry_flag = 1;
	uint64_t chunk_seqnum = 0;
	int j;

	hash_size = hashfile_hash_size(handle) / 8;
	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		if (first_entry_flag) {
			if (show_file_info_only)
				printf("\n");
			printf("%-*s \t\t\tChunk Size (bytes) ",
					hash_size * 2, "Chunk Hash");
			printf("\tCompression Ratio (tenth)");
			printf("\n");
			first_entry_flag = 0;
		}

		print_chunk_info(ci->hash, hash_size,
				ci->size, ci->cratio);

		update_whole_file_hash(ci->hash, hash_size, whole_file_hash);
	}

	if (show_file_info_only)
		first_entry_flag = 1;

	if (show_file_hashes && hashfile_curfile_numchunks(handle) > 0) {
		printf("\nWhole File Hash: ");
		for (j = 0; j < hashfile_hash_size(handle) / 8; j++)
			printf("%.2hhx", whole_file_hash[j]);
		printf("\n");
	}
}

static void compute_whole_file_hash(struct hashfile_handle *handle,
				uint8_t *whole_file_hash)
{
	const struct chunk_info *ci;
	int hash_size;
	static int first_entry_flag = 1;
	uint64_t chunk_seqnum = 0;
	int j;

	hash_size = hashfile_hash_size(handle) / 8;
	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		if (first_entry_flag && !show_file_info_only) {
			printf("%-*s \tFile Path ",
					hash_size * 2, "File Hash");
			printf("\n");
			first_entry_flag = 0;
		}

		update_whole_file_hash(ci->hash, hash_size, whole_file_hash);
	}

	if (show_file_info_only && whole_file_hash) {
		printf("Whole File hash: ");
		for (j = 0; j < hashfile_hash_size(handle) / 8; j++)
			printf("%.2hhx", whole_file_hash[j]);
		printf("\n");
	} else if (!show_file_info_only && whole_file_hash) {
		for (j = 0; j < hashfile_hash_size(handle) / 8; j++)
			printf("%.2hhx", whole_file_hash[j]);
		printf("\t%s", hashfile_curfile_path(handle));
		printf("\n");
	}
}

static void process_hashfile(char *hashfile_name)
{
	struct hashfile_handle *handle;
	uint8_t whole_file_hash[512];
	int ret;
	int first_file = 1;

	handle = hashfile_open(hashfile_name);
	if (!handle)
		liblog_logen(LOG_FTL, errno, "Error opening hash file!");

	update_total_stats(handle);

	if (!show_file_info_only && !show_chunk_hashes && !show_file_hashes) {
		printf("Hash file: %s\n", hashfile_name);
		print_hashfile_header(handle);
		goto out_close;
	}

	/* Going over the files in a hashfile */
	while (1) {
		ret = hashfile_next_file(handle);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Cannot get next file from a hashfile!\n");

		/* exit the loop if it was a last file */
		if (ret == 0)
			break;
	
		if (show_file_info_only && !first_file)
			printf("\n");

		if (show_file_info_only)
			print_current_fileinfo(handle);

		if (show_file_hashes && !show_chunk_hashes
				&& hashfile_curfile_numchunks(handle) > 0) {
			memset(whole_file_hash, 0, sizeof(whole_file_hash));
			compute_whole_file_hash(handle, whole_file_hash);
		}

		if (show_chunk_hashes) {
			memset(whole_file_hash, 0, sizeof(whole_file_hash));
			display_chunk_hashes(handle, whole_file_hash);
		}

		if (first_file)
			first_file = 0;
	}

out_close:

	hashfile_close(handle);

	return;
}

static void usage()
{
	printf("%s {-f|-h|-w|-t} <hashfile> ...\n", progname);
	printf("  -f: Display each file stored in the hash file\n");
	printf("  -h: Display chunk hashes for each file in the hash file\n");
	printf("  -w: Display whole file hash for each file\n");
	printf("  -t: Display information about total chunks, files, etc.\n");
	printf("  -h and -w are mutually exclusive in the absense of -f\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int i;

	/* Save program name */
	progname = argv[0];

	/* Collecting command line parameters */
	while (1) {
		opt = getopt(argc, argv, "hfwt");
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			show_chunk_hashes = 1;
			break;
		case 'f':
			show_file_info_only = 1;
			break;
		case 'w':
			show_file_hashes = 1;
			break;
		case 't':
			show_totals = 1;
			break;
		case '?':
			usage();
			return -1;
		}
	}

	if (optind == argc) {
		liblog_slog(LOG_FTL, "No input files specified!");
		usage();
		return -1;
	}

	if (show_file_hashes && show_chunk_hashes && !show_file_info_only) {
		liblog_slog(LOG_FTL, "-hw must be specified with -f!");
		usage();
		return -1;
	}

	/* Process hashfiles */
	for (i = optind; i < argc; i++) {
		process_hashfile(argv[i]);
		if ((!show_chunk_hashes || show_file_info_only) &&
			(!show_file_hashes || show_file_info_only)
					&& i != argc - 1)
			printf("\n");
	}

	if (show_totals) {
		printf("\n*** Totals for all snapshots ***\n");
		printf("Total files: %" PRIu64 "\n", total_files);
		printf("Total bytes: %" PRIu64 "\n", total_bytes);
		printf("Total chunks: %" PRIu64 "\n", total_chunks);
	}

	return 0;
}
