#ifndef test_evhtp_h
#define test_evhtp_h

#define CLIENT_TEST_IP_LH "127.0.0.1" /* local host */
#define CLIENT_TEST_PORT 80 /* Port 80 for http requests */

void *teststaticfuncptr_getter(char *funcname);
typedef void *(vptr_size_t_func)(size_t);
typedef void (vptr_simple_void)(void);
typedef void (vptr_simple_void_ptr)(void *);

/* Static prototypes in evhtp.c*/
void *htp__malloc_(size_t size);


#endif /* test_evhtp_h */
