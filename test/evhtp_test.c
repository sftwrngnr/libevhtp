/***************************************************/
/* evhtp_test.c                                                        */
/* Unit test for evhtp.c                                            */
/*                                                                            */
/* Written by Dan Henderson                                  */
/* Copyright (C) Critical-stack 2017                        */
/***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <evhtp.h>


#include <test_evhtp.h>
#include <evhtp/evhtp.h>
#include <testcasecalls.h>


int testreturn(int rval)
{
    printf("%s\n", RETVALS[rval]);
    return rval;
}

/* Dummy request_cb*/
static void
dummy_request_cb(evhtp_request_t * req, void * arg)
{
    printf("dummy_request_cb %zu\n", evbuffer_get_length(req->buffer_in));
}

static evhtp_res
print_data(evhtp_request_t * req, evbuf_t * buf, void * arg)
{
    printf("Got %zu bytes\n", evbuffer_get_length(buf));

    return EVHTP_RES_OK;
}

static evhtp_res
print_new_chunk_len(evhtp_request_t * req, uint64_t len, void * arg)
{
    printf("started new chunk, %"  PRIu64 "bytes\n", len);

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunk_complete(evhtp_request_t * req, void * arg)
{
    printf("ended a single chunk\n");

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunks_complete(evhtp_request_t * req, void * arg)
{
    printf("all chunks read\n");

    return EVHTP_RES_OK;
}


static void add_request_callback_hooks(evbase_t *evbase, evhtp_request_t * request)
{
    evhtp_request_set_hook(request, evhtp_hook_on_read, print_data, evbase);
    evhtp_request_set_hook(request, evhtp_hook_on_new_chunk, print_new_chunk_len, NULL);
    evhtp_request_set_hook(request, evhtp_hook_on_chunk_complete, print_chunk_complete, NULL);
    evhtp_request_set_hook(request, evhtp_hook_on_chunks_complete, print_chunks_complete, NULL);
}

/* Create evhtp request with some meaningful data*/
static void add_request_headers(evhtp_request_t *inreq)
{
       evhtp_headers_add_header(inreq->headers_out,
               evhtp_header_new("Host", "byteme.com", 0, 0));
    evhtp_headers_add_header(inreq->headers_out,
                             evhtp_header_new("User-Agent", "libevhtp", 0, 0));
    evhtp_headers_add_header(inreq->headers_out,
                             evhtp_header_new("Connection", "close", 0, 0));
}
int test_evhtp_request_no_callbacks()
{
    evhtp_connection_t * conn = NULL;
    evhtp_request_t *dummyrq = NULL;
    evbase_t           * evbase = NULL;
    int retval = 0;
    evbase  = event_base_new();
    conn = evhtp_connection_new(evbase, CLIENT_TEST_IP_LH, CLIENT_TEST_PORT); /* Shouldn't be an active server */
    dummyrq = evhtp_request_new(dummy_request_cb, evbase);
    /* Should have callbacks to handle stuff*/
    add_request_headers(dummyrq);
     evhtp_make_request(conn, dummyrq, htp_method_GET, "/");
     event_base_loop(evbase, 0);
     event_base_free(evbase);
     /* If we reached here, we've succeeded*/
     retval = 1;
     
    return testreturn(retval);

}


int test_evhtp_request_with_callbacks(void)
{
    evhtp_connection_t * conn = NULL;
    evhtp_request_t *dummyrq = NULL;
    evbase_t           * evbase = NULL;
    int retval = 0;
    evbase  = event_base_new();
    conn = evhtp_connection_new(evbase, CLIENT_TEST_IP_LH, CLIENT_TEST_PORT); /* Shouldn't be an active server */
    dummyrq = evhtp_request_new(dummy_request_cb, evbase);
    /* Add callbacks */
    add_request_callback_hooks(evbase, dummyrq);
    add_request_headers(dummyrq);
     evhtp_make_request(conn, dummyrq, htp_method_GET, "/");
     event_base_loop(evbase, 0);
     event_base_free(evbase);
     /* If we reached here, we've succeeded*/
     retval = 1;
     
    return testreturn(retval);
}

int test_evhtp_static_htp__malloc_(void)
{
    void *myfuncptr = teststaticfuncptr_getter("htp__malloc_");
    void *myMem = NULL;
    int retval = 0;
    
    if (myfuncptr != NULL)
    {
        myMem = ((vptr_size_t_func *) myfuncptr)(100);
        if (NULL != myMem)
        {
            myfuncptr = teststaticfuncptr_getter("htp__free_");
            if (myfuncptr != NULL)
            {
                ((vptr_simple_void_ptr *) myfuncptr)(myMem);
                retval = 1;
            }
            else
            {
                free(myMem);
            }
        }
    }
    return testreturn(retval);
}

tfuncs testfuncarray[] = {
    {"test_evhtp_request_no_callbacks", test_evhtp_request_no_callbacks},
    {"test_evhtp_request_with_callbacks", test_evhtp_request_with_callbacks},
    {"test_evhtp_static_htp__malloc_", test_evhtp_static_htp__malloc_},
    {NULL, NULL}
};



int main(int argc, char ** argp)
{
    int nCount = 0;
    int nRetval = 0;
    int tRet = 0;
    tfuncs *tfptr = NULL;
    for (tfptr  = &testfuncarray[0]; tfptr->testname != NULL; tfptr++)
    {
        printf("Executing [%s] ", tfptr->testname);
        tRet = ((funcptr ) tfptr->mytestfunc) ();
        if ((nRetval == 0) && (tRet == 0))
        {
            nRetval = 1;
        }
        nCount++;
    }
    
    return nRetval; /* Dummy success for now */
}

