#ifndef __RBTREE_API_H__
#define __RBTREE_API_H__

#include "rbtree_augmented.h"

/*
 * 查找"红黑树"中键值为offset的节点。没找到的话，返回NULL。
 */
int rb_search(struct rb_root *root, void* addr, unsigned long *size);

/*
 * 将offset/size插入到红黑树中。插入成功，返回0；失败返回-1。
 */
int rb_insert(struct rb_root *root, void* addr, unsigned long size);

/* 
 * 删除键值为offset的结点
 */
int rb_delete(struct rb_root *root, void* addr, unsigned long* size);

void print_tree(struct rb_root *root);


#endif //__RBTREE_API_H__