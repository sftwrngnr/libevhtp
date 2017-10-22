#ifndef test_evhtp_h
#define test_evhtp_h
#include <stdlib.h>

void * htp__malloc_(size_t size);
void htp__free_(void * ptr);
void *htp__calloc_(size_t nmemb, size_t size);

#endif /* test_evhtp_h */
