/*
 * hashquery.c - CGI to handle SKS style /pks/hashquery requests
 *
 * Copyright 2011 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "build-config.h"
#include "charfuncs.h"
#include "cleanup.h"
#include "keydb.h"
#include "log.h"
#include "marshal.h"
#include "mem.h"
#include "onak-conf.h"

/*
 * The largest request we will read, in bytes.
 *
 * A reconciliation request is an array of 16 byte hashes, so a mebibyte
 * holds some sixty thousand of them — far past what a peer ever sends. A
 * ceiling is needed at all because the size below is what the client
 * *claims* in Content-Length, believed and allocated before a single byte
 * of the body has been read: without it, one request announcing two
 * gigabytes gets two gigabytes.
 */
#define MAX_QUERY_SIZE (1024 * 1024)

/*
 * Every error also says so in the status line. They used to leave it at
 * the default, so a refused request came back 200 OK with the refusal in
 * the body — a caller has no way to tell that from an answer.
 */
void doerror(const char *status, char *error)
{
	printf("Status: %s\n", status);
	printf("Content-Type: text/plain\n\n");
	printf("%s", error);
	cleanuplogthing();
	cleanupconfig();
	exit(EXIT_FAILURE);
}

int main(__unused int argc, __unused char *argv[])
{
	char *request_method, *env;
	int count, found, i;
	uint8_t **hashes;
	struct buffer_ctx cgipostbuf;
	struct openpgp_publickey **keys;
	struct onak_dbctx *dbctx;

	readconfig(NULL);
	initlogthing("hashquery", config.logfile);

	request_method = getenv("REQUEST_METHOD");
	if (request_method == NULL || strcmp(request_method, "POST") != 0) {
		doerror("405 Method Not Allowed",
			"hashquery must be a HTTP POST request.\n");
	}

	env = getenv("CONTENT_LENGTH");
	if ((env == NULL) || !(cgipostbuf.size = atoi(env))) {
		doerror("411 Length Required",
			"Must provide a content length.\n");
	}

	if (cgipostbuf.size > MAX_QUERY_SIZE) {
		logthing(LOGTHING_NOTICE,
			"Refused a %zu byte hashquery request (max %d).",
			cgipostbuf.size, MAX_QUERY_SIZE);
		doerror("413 Payload Too Large",
			"Query too large.\n");
	}

	cgipostbuf.offset = 0;
	cgipostbuf.buffer = malloc(cgipostbuf.size);
	if (cgipostbuf.buffer == NULL) {
		doerror("500 Internal Server Error",
			"Couldn't allocate memory for query content.\n");
	}

	if (!fread(cgipostbuf.buffer, cgipostbuf.size, 1, stdin)) {
		doerror("400 Bad Request", "Couldn't read query.\n");
	}

	hashes = (uint8_t **) unmarshal_array(buffer_fetchchar, &cgipostbuf,
			(void * (*)(size_t (*)(void *, size_t,  void *), void *))
				unmarshal_skshash, &count);

	free(cgipostbuf.buffer);
	cgipostbuf.buffer = NULL;
	cgipostbuf.size = cgipostbuf.offset = 0;

	if (hashes == NULL) {
		doerror("400 Bad Request", "No hashes supplied.\n");
	}

	found = 0;
	keys = calloc(sizeof(struct openpgp_publickey *), count);
	if (keys == NULL) {
		doerror("500 Internal Server Error",
			"Couldn't allocate memory for reply.\n");
	}

	catchsignals();
	dbctx = config.dbinit(config.backend, false);

	if (dbctx == NULL) {
		doerror("500 Internal Server Error",
			"Failed to open key database.");
	}

	if (dbctx->fetch_key_skshash == NULL) {
		dbctx->cleanupdb(dbctx);
		doerror("501 Not Implemented",
			"Can't fetch by skshash with this backend.");
	}

	for (i = 0; i < count; i++) {
		dbctx->fetch_key_skshash(dbctx,
				(struct skshash *) hashes[i], &keys[found]);
		if (keys[found] != NULL) {
			found++;
		}
		free(hashes[i]);
		hashes[i] = NULL;
	}
	free(hashes);
	hashes = NULL;

	dbctx->cleanupdb(dbctx);

	puts("Content-Type: pgp/keys\n");
	marshal_array(stdout_putchar, NULL,
			(void (*)(size_t (*)(void *, size_t,  void *),
					void *, const void *))
				marshal_publickey, (void **) keys, found);
	printf("\n");

	for (i = 0; i < found; i++) {
		free_publickey(keys[i]);
	}
	free(keys);

	cleanuplogthing();
	cleanupconfig();
}
