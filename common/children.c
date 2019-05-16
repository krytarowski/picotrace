/*	$NetBSD$	*/

/*-
 * Copyright (c) 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Kamil Rytarowski.
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
__RCSID("$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/rbtree.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <util.h>

/*
 * The int type for key assumes:
 *   sizeof(pid_t) == sizeof(lwpid_t) == sizeof(int)
 *
 * The value pointer is a shallow copy of an object.
 */
struct children_pair_entry {
	int first;  /* key   */
	void *second; /* value */
	rb_node_t pair_node;
};

static int
children_compare_key(void *ctx, const void *n1, const void *keyp)
{
	int a1;
	int a2;

	assert(n1);
	assert(keyp);

	a1 = ((struct children_pair_entry*)n1)->first;
	a2 = (int)(intptr_t)keyp;

	if (a1 < a2)
		return 1;
	if (a1 > a2)
		return -1;
	return 0;
}

static int
children_compare_nodes(void *ctx, const void *n1, const void *n2)
{
	int key2;

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

struct children_tree_type {
	rb_tree_t children_tree;
	rb_tree_t children_vars_tree;
};

void *
children_tree_init(void)
{
	struct children_tree_type *tree;
	int ret;

	tree = emalloc(sizeof(struct children_tree_type));

	rb_tree_init(&tree->children_tree, &children_tree_ops);

	return tree;
}

int
children_tree_insert(void *tree, int entry, void *value)
{
	struct children_pair_entry *pair;
	struct children_pair_entry *opair;

	assert(tree);
	assert(entry > 0);

	pair = emalloc(sizeof(*pair));

	pair->first = entry;
	pair->second = value; /* shallow copy */

	opair = rb_tree_insert_node(tree, pair);
	assert (opair == pair);

	return 0;
}

int
children_tree_remove(void *tree, int entry)
{
	struct children_pair_entry *pair;

	assert(tree);
	assert(entry > 0);

	pair = rb_tree_find_node(tree, (void *)(intptr_t)entry);
	assert(pair != NULL);

	rb_tree_remove_node(tree, pair);

	free(pair);

	return 0;
}

void *
children_tree_find(void *tree, int entry)
{
	struct children_pair_entry *pair;

	assert(tree);
	assert(entry > 0);

	pair = rb_tree_find_node(tree, (void *)(intptr_t)entry);
	if (pair == NULL)
		return NULL;

	return pair->second;
}

int
children_tree_dump(void *tree, void (*callback)(int))
{
	struct children_pair_entry *pair;

	assert(tree);
	assert(callback);

	RB_TREE_FOREACH(pair, tree) {
		assert(pair);

		(*callback)(pair->first);
	}

	return 0;
}
