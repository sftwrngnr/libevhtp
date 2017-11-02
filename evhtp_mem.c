/**
 *  @file evhtp_mem.c
 * @brief File containing the memory allocation and management functions explicitly used within the evhtp library.
 *
 *
 *
 * @author Dan Henderson
 *
 * @copyright Critical Stack (2017)
 */

/* Include files*/
#include <stdlib.h>
#include <evhtp.h>
#include <internal.h> /* Maybe change this to libevhtp_internal.h */
#include <evhtp/evhtpdefs.h>
#include <evhtp/evhtpstructs.h>
#include <string.h>

#ifndef EVHTP_DISABLE_MEMFUNCTIONS

static void * (*malloc_)(size_t sz) = malloc;
static void * (* realloc_)(void * d, size_t sz) = realloc;
static void   (* free_)(void * d) = free;

static void *
htp__malloc_(size_t size)
{
    return malloc_(size);
}

static void *
htp__realloc_(void * ptr, size_t size)
{
    return realloc_(ptr, size);
}

static void
htp__free_(void * ptr)
{
    return free_(ptr);
}

static void *
htp__calloc_(size_t nmemb, size_t size)
{
    if (malloc_ != malloc)
    {
        size_t len = nmemb * size;
        void * p;

        if ((p = malloc_(len)) == NULL)
        {
            return NULL;
        }

        memset(p, 0, len);

        return p;
    }

    return calloc(nmemb, size);
}

static char *
htp__strdup_(const char * str)
{
    if (malloc_ != malloc)
    {
        size_t len;
        void * p;

        len = strlen(str);

        if ((p = malloc_(len + 1)) == NULL)
        {
            return NULL;
        }

        memcpy(p, str, len + 1);

        return p;
    }

    return strdup(str);
}

static char *
htp__strndup_(const char * str, size_t len)
{
    if (malloc_ != malloc)
    {
        char * p;

        if ((p = malloc_(len + 1)) != NULL)
        {
            memcpy(p, str, len + 1);
        } else {
            return NULL;
        }

        p[len] = '\0';

        return p;
    }

    return strndup(str, len);
}

#else
#define htp__malloc_(sz)     malloc(sz)
#define htp__calloc_(n, sz)  calloc(n, sz)
#define htp__strdup_(s)      strdup(s)
#define htp__strndup_(n, sz) strndup(n, sz)
#define htp__realloc_(p, sz) realloc(p, sz)
#define htp__free_(p)        free(p)
#endif

TAILQ_ENTRY(evhtp_callback_s) next;

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

static void
htp__default_request_cb_(evhtp_request_t * request, void * arg)
{
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Content-Length", "0", 0, 0));
    evhtp_send_reply(request, EVHTP_RES_NOTFOUND);
}

void evhtp_callbacks_free(evhtp_callbacks_t * callbacks); /* TODO: Put this in a header. */

void
evhtp_set_mem_functions(void *(*mallocfn_)(size_t len),
                        void *(*reallocfn_)(void * p, size_t sz),
                        void (* freefn_)(void * p))
{
#ifndef EVHTP_DISABLE_MEMFUNCTIONS
    malloc_  = mallocfn_;
    realloc_ = reallocfn_;
    free_    = freefn_;

    return event_set_mem_functions(malloc_, realloc_, free_);
#endif
}

/*
 * COMPAT FUNCTIONS
 */

#ifdef NO_STRNLEN
static size_t
strnlen(const char * s, size_t maxlen)
{
    const char * e;
    size_t       n;

    for (e = s, n = 0; *e && n < maxlen; e++, n++)
    {
        ;
    }

    return n;
}

#endif

#ifdef NO_STRNDUP
static char *
strndup(const char * s, size_t n)
{
    size_t len = strnlen(s, n);
    char * ret;

    if (len < n)
    {
        return htp__strdup_(s);
    }

    if ((ret = htp__malloc_(n + 1)) == NULL)
    {
        return NULL;
    }

    ret[n] = '\0';

    memcpy(ret, s, n);

    return ret;
}

#endif

static int
evhtp__new_(evhtp_t ** out, struct event_base * evbase, void * arg)
{
    evhtp_t * htp;


    if (evhtp_unlikely(evbase == NULL))
    {
        return -1;
    }

    *out = NULL;

    if ((htp = htp__calloc_(1, sizeof(*htp))) == NULL)
    {
        return -1;
    }


    htp->arg          = arg;
    htp->evbase       = evbase;
    htp->flags        = EVHTP_FLAG_DEFAULTS;
    htp->bev_flags    = BEV_OPT_CLOSE_ON_FREE;

    /* default to lenient argument parsing */
    htp->parser_flags = EVHTP_PARSE_QUERY_FLAG_DEFAULT;


    TAILQ_INIT(&htp->vhosts);
    TAILQ_INIT(&htp->aliases);

    /* note that we pass the htp context to the callback,
     * not the user supplied arguments. That is stored
     * within the context itself.
     */
    evhtp_set_gencb(htp, htp__default_request_cb_, (void *)htp);

    *out = htp;

    return 0;
}

/**
 * @brief allocate new htp structure.
 *
 * @param evbase event_base structure
 * @param arg arguments for creating the htp structure
 *
 * @return newly allocated structure, or NULL on failure
 */
evhtp_t *
evhtp_new(struct event_base * evbase, void * arg)
{
    evhtp_t * htp;

    if (evhtp__new_(&htp, evbase, arg) == -1)
    {
        return NULL;
    }

    return htp;
}


void
evhtp_free(evhtp_t * evhtp)
{
    evhtp_alias_t * evhtp_alias, * tmp;

    if (evhtp == NULL)
    {
        return;
    }

#ifndef EVHTP_DISABLE_EVTHR
    if (evhtp->thr_pool)
    {
        evthr_pool_stop(evhtp->thr_pool);
        evthr_pool_free(evhtp->thr_pool);
    }
#endif

#ifndef EVHTP_DISABLE_SSL
    if (evhtp->ssl_ctx)
    {
        evhtp_safe_free(evhtp->ssl_ctx, SSL_CTX_free);
    }
#endif

    if (evhtp->server_name)
    {
        evhtp_safe_free(evhtp->server_name, htp__free_);
    }

    if (evhtp->callbacks)
    {
        evhtp_safe_free(evhtp->callbacks, evhtp_callbacks_free);
    }

    TAILQ_FOREACH_SAFE(evhtp_alias, &evhtp->aliases, next, tmp)
    {
        if (evhtp_alias->alias != NULL)
        {
            evhtp_safe_free(evhtp_alias->alias, htp__free_);
        }

        TAILQ_REMOVE(&evhtp->aliases, evhtp_alias, next);
        evhtp_safe_free(evhtp_alias, htp__free_);
    }

    evhtp_safe_free(evhtp, htp__free_);
}     /* evhtp_free */

#ifdef TEST_STATIC_FUNCS
typedef struct staticfuncs
{
    char *sfuncname;
    void *sfuncptr;
} sfuncs;

sfuncs sfuncarray[] = {
    {"htp__malloc_", htp__malloc_},
    {"htp__realloc_", htp__realloc_},
    {"htp__free_", htp__free_},
    {NULL, NULL}
};

void *test_static_evhtp_mem_getter(char *funcname) /* Avoid name collisions by ensuring that these functions are named test_static_<module_name>_getter */
{
    sfuncs *myptr = NULL;
    void *funcptr = NULL;
    if (NULL != funcname)
    {
        myptr = sfuncarray;
        while (myptr->sfuncname != NULL)
        {
            if (strcmp(funcname, myptr->sfuncname) == 0)
            {
                funcptr = myptr->sfuncptr;
                return funcptr;
            }
            else
                myptr++;
        }
    }
    return (void *) NULL; /* Couldn't find it */
}

void *htp__malloc(size_t size)
{
    return htp__malloc_(size);
}

void *htp__calloc(size_t nmemb, size_t size)
{
    return htp__calloc_(nmemb, size);
}

void htp__free(void *ptr)
{
    htp__free_(ptr);
}

char *htp__strndup(const char * str, size_t len)
{
    return htp__strndup_(str, len);
}

char *htp__strdup(const char *str)
{
    return htp__strdup_(str);
}


#endif /* TEST_STATIC_FUNCS */
