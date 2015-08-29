/*
 * Copyright (c) 2011-2014 Vasily Tarasov
 * Copyright (c) 2011-2014 Philip Shilane
 * Copyright (c) 2011-2014 Erez Zadok
 * Copyright (c) 2011-2014 Geoff Kuenning
 * Copyright (c) 2011-2014 Stony Brook University
 * Copyright (c) 2011-2014 Harvey Mudd College
 * Copyright (c) 2011-2014 The Research Foundation of the State University of New York
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "liblog.h"

#define MAX_LOG_RECORD_LEN	512
#define DEFAULT_LOG_LEVEL	LOG_INF

static char log_record[MAX_LOG_RECORD_LEN];
static int current_log_level = DEFAULT_LOG_LEVEL;

void liblog_set_log_level(int level)
{
	current_log_level = level;
}

void logit_exit();

/*
 * Most generic log function, called by others.
 * level - determines the priority of the message.
 *	This in turn decides:
 *	1) if anything should be printed at all
 *	(depending on the current log level)
 *	2) what will be the prefix (INF, WRN, etc.)
 * exitcode - should program exit and with what exit code
 * errno - should string presentation of errno be printed
 * 	   and which errno is it.
 *
 * All log messages go to stderr.
 */
static void do_logit(int level, int exitcode, int errnum, char *fmt, va_list ap)
{
	char *log_record_cur;
	char *errno_str;
	int len;

	/* decide if we should print this message at all */
	if (level > current_log_level)
		return;

	log_record_cur = log_record;


	/* decide which prefix to use */
	switch(level) {
	case LOG_DBG:
		strcpy(log_record_cur, "[DBG] ");
		len = strlen("[DBG] ");
		break;
	case LOG_INF:
		strcpy(log_record_cur, "[INF] ");
		len = strlen("[INF] ");
		break;
	case LOG_WRN:
		strcpy(log_record_cur, "[WRN] ");
		len = strlen("[WRN] ");
		break;
	case LOG_ERR:
		strcpy(log_record_cur, "[ERR] ");
		len = strlen("[ERR] ");
		break;
	case LOG_FTL:
		strcpy(log_record_cur, "[FTL] ");
		len = strlen("[FTL] ");
		break;
	default:
		fprintf(stderr, "[ERR] Unsupported log level!\n");
		strcpy(log_record_cur, "[WRD] ");
		len = strlen("[WRD] ");
		break;
	}

	log_record_cur += len;

	/* adding the message itself */
	len = vsnprintf(log_record_cur, MAX_LOG_RECORD_LEN - len, fmt, ap);
	log_record_cur += len;

	/* add string representation of errno if needed */
	if (errnum) {
		errno_str = strerror(errnum);
		len = snprintf(log_record_cur,
			 MAX_LOG_RECORD_LEN, " %s.", errno_str);
	}

	fprintf(stderr, "%s\n", log_record);

	/* decide if we should exit */
	if (exitcode)
		exit(exitcode);
}

/* simple log */
void liblog_slog(int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	do_logit(level, 0, 0, fmt, ap);
}

/* simple log that exits */
void liblog_sloge(int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	do_logit(level, -1, 0, fmt, ap);
}

/* prints errno */
void liblog_logn(int level, int error_num, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	do_logit(level, 0, error_num, fmt, ap);
}

/* prints errno and exits */
void liblog_logen(int level, int error_num, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	do_logit(level, -1, error_num, fmt, ap);
}
