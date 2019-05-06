/* $NetBSD: plist_tree.c,v 1.4 2018/02/23 06:31:34 adam Exp $ */

/*-
 * Copyright (c) 2016 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD: plist_tree.c,v 1.4 2018/02/23 06:31:34 adam Exp $");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/rbtree.h>
#include <assert.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

struct children_pair_entry {
	pid_t first;  /* key   */
	pid_t second; /* value */
	rb_node_t pair_node;
};

static int
children_compare_key(void *ctx, const void *n1, const void *keyp)
{
	pid_t a1;
	pid_t a2;

	assert(n1);
	assert(keyp);

	a1 = ((struct children_pair_entry*)n1)->first;
	a2 = (pid_t)(intptr_t)keyp;

	return a1 != a2;
}

static int
children_compare_nodes(void *ctx, const void *n1, const void *n2)
{
	pid_t key2;

	assert(n1);
	assert(n2);

	key2 = ((struct children_pair_entry*)n2)->first;

	return children_compare_key(ctx, n1, (void *)(intptr_t)key2);
}

static const rb_tree_ops_t children_tree_ops = {
	.rbto_compare_nodes = children_compare_nodes,
	.rbto_compare_key = children_compare_key,
	.rbto_node_offset = offsetof(struct children_pair_entry, pair_node),
	.rbto_context = NULL,
};

/* children_tree_singleton */

static struct children_tree_type {
	rb_tree_t children_tree;
	rb_tree_t children_vars_tree;
	int initialized;
	regex_t children_regex_options;
} children_tree_singleton = {
	.initialized = 0
};

void
children_tree_init(void)
{
	int ret;

	assert(children_tree_singleton.initialized == 0);

	rb_tree_init(&children_tree_singleton.children_tree, &children_tree_ops);

	children_tree_singleton.initialized = 1;
}

int
children_tree_insert(pid_t entry)
{
	struct children_pair_entry *pair;
	struct children_pair_entry *opair;

	assert(children_tree_singleton.initialized == 1);

	pair = malloc(sizeof(*pair));
	if (pair == NULL)
		err(EXIT_FAILURE, "malloc");

	pair->first = entry;
	pair->second = entry;

	opair = rb_tree_insert_node(&children_tree_singleton.children_tree, pair);
	assert (opair == pair);

	return 0;
}

int
children_tree_remove(pid_t entry)
{
	struct children_pair_entry *pair;

	assert(children_tree_singleton.initialized == 1);
	assert(entry);

	pair = rb_tree_find_node(&children_tree_singleton.children_tree, (void *)(intptr_t)entry);
	assert(pair != NULL);

        rb_tree_remove_node(&children_tree_singleton.children_tree, pair);

	free(pair);

	return 0;
}

int
children_tree_dump(void (*callback)(pid_t))
{
	struct children_pair_entry *pair;

	assert(callback);
        assert(children_tree_singleton.initialized == 1);

	RB_TREE_FOREACH(pair, &children_tree_singleton.children_tree) {
		assert(pair);

		(*callback)(pair->first);
	}

	return 0;
}
