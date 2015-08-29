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
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 */

#define LOG_FTL		1	/* error, cannot continue, call exit() */
#define LOG_ERR		2	/* error, but we can continue */
#define LOG_WRN		3	/* something unusual, but not an error */
#define LOG_INF		4	/* information */
#define LOG_DBG		5	/* debug */

/*
 * sets log level
 */
extern void liblog_set_log_level(int level);

/*
 * simple log
 */
extern void liblog_slog(int level, char *fmt, ...);

/*
 * simple log that exits (with default exit code)
 */
extern void liblog_sloge(int level, char *fmt, ...);

/*
 * prints string errno and exits
 */
void liblog_logn(int level, int error_num, char *fmt, ...);

/*
 * prints string errno and exits
 */
extern void liblog_logen(int level, int error_num, char *fmt, ...);
