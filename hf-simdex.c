/*
 * Copyright (c) 2011	   Amar Mudrankit
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

#define _XOPEN_SOURCE 500
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "list.h"
#include "rbtree.h"
#include "libhashfile.h"

#define MAX_HASH_SIZE 128	/* in bytes */

/*************************** LIST-BASED INDEXING ******************************/

#define LISTBASED_INDEXING_BITS		8
#define LISTBASED_INDEXING_TABLE_SIZE	1 << LISTBASED_INDEXING_BITS

struct listbased_hash_element {
	unsigned char *key;
	int keysz; /* in bytes */
	char *value;

	struct list_head bucket_list;
};

static struct list_head *listbased_hash_table;

static int listbased_init_key_value_store()
{
	int i;

	listbased_hash_table = malloc(sizeof(struct list_head)
					 * LISTBASED_INDEXING_TABLE_SIZE);
	if (!listbased_hash_table)
		return -1;

	for (i = 0; i < LISTBASED_INDEXING_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&listbased_hash_table[i]);

	return 0;
}

static int listbased_store_key_value(unsigned char *key, int keysz, char *value)
{
	int hash;
	struct listbased_hash_element *el;
	struct listbased_hash_element *newel;

	hash = (int)key[0];

	list_for_each_entry(el, &listbased_hash_table[hash], bucket_list) {
		if (!memcmp((char *)el->key, (char *)key, keysz)) {
			return 1; /* duplicate found */
		}
	}

	/* No duplicates found => allocate entry */
	newel = malloc(sizeof(*newel));
	if (!newel)
		return -1;

	newel->key = malloc(keysz);
	if (!newel->key) {
		free(newel);
		return -1;
	}

	memcpy((char *)newel->key, (char *)key, keysz);
	newel->keysz = keysz;
	newel->value = value;
	list_add(&newel->bucket_list, &listbased_hash_table[hash]);

	return 0;
}

/************************ RED-BLACK TREE INDEXING *****************************/

#define RBTREE_INDEXING_BITS		8
#define RBTREE_INDEXING_TABLE_SIZE	1 << RBTREE_INDEXING_BITS

struct rbtree_hash_element {
	unsigned char *key;
	int keysz; /* in bytes */
	char *value;
	struct rb_node node;
	int duplicate_count;
};

struct rb_root *rbtree_hash_table;

static int rbtree_init_key_value_store()
{
	int i;

	rbtree_hash_table = malloc(sizeof(struct rb_root)
					 * RBTREE_INDEXING_TABLE_SIZE);
	if (!rbtree_hash_table)
		return -1;

	for (i = 0; i < RBTREE_INDEXING_TABLE_SIZE; i++)
		rbtree_hash_table[i] = RB_ROOT;

	return 0;
}

static int search_rbtree(struct rb_root *root, unsigned char *key)
{
	int result;
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rbtree_hash_element *ele =
			 container_of(node, struct rbtree_hash_element, node);

		result = memcmp((char *)key, (char *)ele->key, ele->keysz);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			ele->duplicate_count++;
			return 0;
		}
	}
	return 1;
}

static int rbtree_insert(struct rb_root *root, struct rbtree_hash_element *ele)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct rbtree_hash_element *this =
			 container_of(*new, struct rbtree_hash_element, node);
		int result = memcmp((char *)ele->key, (char *)this->key,
								 this->keysz);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return 1;
	}

	rb_link_node(&ele->node, parent, new);
	rb_insert_color(&ele->node, root);

	return 0;
}

static int rbtree_store_key_value(unsigned char *key, int keysz, char *value)
{
	int ret, hash;
	struct rbtree_hash_element *newel;

	hash = (int)key[0];

	ret = search_rbtree(&rbtree_hash_table[hash], key);
	if (!ret)
		return 1;

	/* No duplicates found => allocate entry */
	newel = malloc(sizeof(struct rbtree_hash_element));
	if (!newel)
		return -1;

	newel->key = malloc(keysz);
	if (!newel->key) {
		free(newel);
		return -1;
	}

	memcpy((char *)newel->key, (char *)key, keysz);
	newel->keysz = keysz;
	newel->value = value;
	newel->duplicate_count = 0;
	rbtree_insert(&rbtree_hash_table[hash], newel);

	return 0;
}

/************************** GENERIC INDEXING API ******************************/

#define INDEXING_METHOD_NAME_MAX_LEN	256

struct indexing_method {
	char name[INDEXING_METHOD_NAME_MAX_LEN];
	int (*init_key_value_store)();
	/*
	 * store_key_value() returns 1 if a duplicate was detected,
	 * 0 if the insertion happened successfully, and a negative value
	 * if an error has occurred.
	 */
	int (*store_key_value)(unsigned char *key, int keysz, char *value);
};

static struct indexing_method *idx_method;

struct indexing_method idx_methods[] = {
	{
		.name = "list",
		.init_key_value_store = listbased_init_key_value_store,
		.store_key_value = listbased_store_key_value
	},
	{
		.name = "rbtree",
		.init_key_value_store = rbtree_init_key_value_store,
		.store_key_value = rbtree_store_key_value
	}
};

/******************************** PROCESS FILE ********************************/

struct skip_hash
{
	char hash[MAX_HASH_SIZE];
	int hashsize;
	struct skip_hash *next;
};

static struct skip_hash *skip_hash_list;

static int skip_hash(uint8_t *hash, int hashsize)
{
	struct skip_hash *sh = skip_hash_list;

	while (sh) {
		if (hashsize != sh->hashsize)
			continue;

		if (!memcmp(sh->hash, hash, hashsize))
			return 1;

		sh = sh->next;
	}

	return 0;
}

static void print_progress(uint64_t total, uint64_t progress)
{
	static time_t prev_progress_time = 0;

	if (!prev_progress_time) {
		prev_progress_time = time(NULL);
		return;
	}

	if (time(NULL) - prev_progress_time > 5) {
		printf("%"PRIu64" of %"PRIu64" chunks processed.\n",
			progress, total);
		prev_progress_time = time(NULL);
	}
}

static int process_hashfile(char *file, uint64_t *file_count,
			 uint64_t *chunk_count, uint64_t *duplicate_chunk_count,
			 uint64_t *bytes_count, uint64_t *duplicate_bytes_count)
{
	int ret;
	struct hashfile_handle *handle;
	const struct chunk_info *chunk;
	uint64_t hashfile_chunks, hashfile_chunk_count;

	printf("Processing %s...\n", file);

	handle = hashfile_open(file);
	if (!handle) {
		perror("Failed to open hash file");
		return -1;
	}

	hashfile_chunks = hashfile_numchunks(handle);
	hashfile_chunk_count = 0;

	while (1) {
		ret = hashfile_next_file(handle);
		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Error processing hash file");
			goto out;
		}

		(*file_count)++;

		while (1) {
			chunk = hashfile_next_chunk(handle);
			if (!chunk)
				break;

			if (skip_hash(chunk->hash, handle->header.hash_size / 8))
				continue;

			ret = idx_method->store_key_value(chunk->hash,
					handle->header.hash_size / 8, NULL);
			if (ret < 0) {
				fprintf(stderr,
					"Failed to insert key into index!\n");
				goto out;
			}

			hashfile_chunk_count++;
			(*chunk_count)++;
			(*bytes_count) += chunk->size;
			if (ret == 1) {
				(*duplicate_chunk_count)++;
				(*duplicate_bytes_count) += chunk->size;
			}

			print_progress(hashfile_chunks, hashfile_chunk_count);
		}
	}

	ret = 0;

	printf("Done!\n");
out:
	hashfile_close(handle);
	return ret;
}

/*********************************** MAIN *************************************/

static char *progname;

static void usage()
{
	printf("Usage: %s [-i <list|rbtree>] [-s <hash>] hashfile ...\n",
								progname);
	printf("  -i: indexing method. Default is rbtree\n");
	printf("  -s: exclude specified hashes from statistics. "
			"Can be specified multiple times\n");
}

static int str_hash_to_number(char *hash_str, char *hash)
{
	int i, j;
	char hexbuf[3];
	char *hashpos = hash;
	int hashlen;
	int set;

	hexbuf[2] = '\0';

	i = 0;
	j = i + 1;
	set = 0;
	while (hash_str[i] != '\0') {
		if ((j % 3) == 0) {
			if (hash_str[i] != ':')
				return -1;
			sscanf(hexbuf, "%x", (unsigned int *)hashpos);
			hashpos += 1;
			set = 0;
		} else if (!set) {
			if (!isxdigit(hash_str[i]))
				return -1;
			hexbuf[0] = hash_str[i];
			set++;
		} else {
			if (!isxdigit(hash_str[i]))
				return -1;
			hexbuf[1] = hash_str[i];
			set++;
		}

		i++;
		j++;
	}

	if (set != 2)
		return -1;

	sscanf(hexbuf, "%x", (unsigned int *)hashpos);

	hashlen = j / 3;

	return hashlen;
}

static int skip_hash_add(char *hash, int hashsize)
{
	struct skip_hash *sh;

	sh = (struct skip_hash *)malloc(sizeof(*sh));
	if (!sh)
		return -1;

	memcpy(sh->hash, hash, hashsize);
	sh->hashsize = hashsize;

	if (!skip_hash_list)
		sh->next = NULL;
	else
		sh->next = skip_hash_list;

	skip_hash_list = sh;

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	int i;
	int ret;
	char *idx_method_str = "rbtree";
	char *skip_hash_str = NULL;
	uint64_t file_count = 0, chunk_count = 0, duplicate_chunk_count = 0;
	uint64_t bytes_count = 0, duplicate_bytes_count= 0;
	char skip_hash[MAX_HASH_SIZE];
	int hashlen;

	progname = argv[0];

	/* Process arguments */
	while (1) {
		opt = getopt(argc, argv, "i:s:");
		if (opt == -1)
			break;

		switch (opt) {
		case 'i':
			idx_method_str = optarg;
			break;
		case 's':
			skip_hash_str = optarg;
			hashlen = str_hash_to_number(skip_hash_str, skip_hash);
			if (hashlen < 0) {
				printf("Could not parse hash!\n");
				return -1;
			}
			ret = skip_hash_add(skip_hash, hashlen);
			if (ret < 0) {
				printf("Could not add skip hash!\n");
				return -1;
			}
			break;
		case '?':
			usage();
			return -1;
		}
	}

	for (i = 0; i < sizeof(idx_methods) /
				sizeof(struct indexing_method); i++) {
		if (!strcmp(idx_methods[i].name, idx_method_str)) {
			idx_method = &idx_methods[i];
			break;
		}
	}

	if (!idx_method) {
		fprintf(stderr, "Unrecognized indexing method %s!\n",
							 idx_method_str);
		usage();
		return -1;
	}

	if (optind == argc) {
		fprintf(stderr, "No input files specified!\n");
		usage();
		return -1;
	}

	/* Create index */
	ret = idx_method->init_key_value_store();
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize index!\n");
		return -1;
	}

	/* Process input files */
	for (i = optind; i < argc; i++) {
		ret = process_hashfile(argv[i], &file_count,
					&chunk_count, &duplicate_chunk_count,
					&bytes_count, &duplicate_bytes_count);
		if (ret < 0) {
			fprintf(stderr, "Fatal error while processing %s!\n",
				argv[i]);
			return -1;
		}
	}

	/* Print statistics */
	printf("%"PRIu64" Files\n", file_count);
	printf("%"PRIu64" Chunks\n", chunk_count);
	printf("%"PRIu64" Bytes\n", bytes_count);
	printf("%"PRIu64" Duplicate chunks\n", duplicate_chunk_count);
	printf("%"PRIu64" Duplicate bytes\n", duplicate_bytes_count);
	printf("%f Logical chunks / Physical chunks\n",
	    ((float)chunk_count / (chunk_count - duplicate_chunk_count)));
	printf("%f Logical bytes / Physical bytes\n",
	    ((float)bytes_count / (bytes_count - duplicate_bytes_count)));

	return 0;
}
