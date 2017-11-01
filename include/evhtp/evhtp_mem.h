/***
 * evhtp_mem.h
 * Header file containing evhtp_mem prototypes.
 *
 * @author Dan Henderson
 * @copyright Copyright (C) 2017 Critical Stack
 *
 * **/

#ifndef evhtp_mem_h
#define evhtp_mem_h

void *htp__malloc(size_t);
void *htp__calloc(size_t, size_t);
void htp__free(void *ptr);
char *htp__strndup_(const char * str, size_t len);
char *htp__strdup(const char * str);

#ifdef TEST_STATIC_FUNCS
void *test_static_evhtp_mem_getter(char *funcname);
#endif /* TEST_STATIC_FUNCS */



#endif /* evhtp_mem_h */
