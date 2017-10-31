#ifndef evhtpstructs_h_
#define evhtpstructs_h_

#include <stdint.h>

struct evhtp_callback_s;
struct evhtp_callbacks_s;

#ifndef EVHTP_DISABLE_SSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifndef EVHTP_DISABLE_SSL
typedef SSL_SESSION               evhtp_ssl_sess_t;
typedef SSL                       evhtp_ssl_t;
typedef SSL_CTX                   evhtp_ssl_ctx_t;
typedef X509                      evhtp_x509_t;
typedef X509_STORE_CTX            evhtp_x509_store_ctx_t;
#else
typedef void                      evhtp_ssl_sess_t;
typedef void                      evhtp_ssl_t;
typedef void                      evhtp_ssl_ctx_t;
typedef void                      evhtp_x509_t;
typedef void                      evhtp_x509_store_ctx_t;
#endif

typedef struct evbuffer           evbuf_t;
typedef struct event              event_t;
typedef struct evconnlistener     evserv_t;
typedef struct bufferevent        evbev_t;

#ifdef EVHTP_DISABLE_EVTHR
typedef struct event_base         evbase_t;
typedef void                      evthr_t;
typedef void                      evthr_pool_t;
typedef void                      evhtp_mutex_t;
#else
typedef pthread_mutex_t           evhtp_mutex_t;
#endif

typedef struct evhtp_s            evhtp_t;
typedef struct evhtp_defaults_s   evhtp_defaults_t;
typedef struct evhtp_callbacks_s  evhtp_callbacks_t;
typedef struct evhtp_callback_s   evhtp_callback_t;
typedef struct evhtp_defaults_s   evhtp_defaults_5;
typedef struct evhtp_kv_s         evhtp_kv_t;
typedef struct evhtp_kvs_s        evhtp_kvs_t;
typedef struct evhtp_uri_s        evhtp_uri_t;
typedef struct evhtp_path_s       evhtp_path_t;
typedef struct evhtp_authority_s  evhtp_authority_t;
typedef struct evhtp_request_s    evhtp_request_t;
typedef struct evhtp_hooks_s      evhtp_hooks_t;
typedef struct evhtp_connection_s evhtp_connection_t;
typedef struct evhtp_ssl_cfg_s    evhtp_ssl_cfg_t;
typedef struct evhtp_alias_s      evhtp_alias_t;
typedef uint16_t                  evhtp_res;
typedef uint8_t                   evhtp_error_flags;


#define evhtp_header_s  evhtp_kv_s
#define evhtp_headers_s evhtp_kvs_s
#define evhtp_query_s   evhtp_kvs_s

#define evhtp_header_t  evhtp_kv_t
#define evhtp_headers_t evhtp_kvs_t
#define evhtp_query_t   evhtp_kvs_t

enum evhtp_ssl_scache_type {
    evhtp_ssl_scache_type_disabled = 0,
    evhtp_ssl_scache_type_internal,
    evhtp_ssl_scache_type_user,
    evhtp_ssl_scache_type_builtin
};

/**
 * @brief types associated with where a developer can hook into
 *        during the request processing cycle.
 */
enum evhtp_hook_type {
    evhtp_hook_on_header,       /**< type which defines to hook after one header has been parsed */
    evhtp_hook_on_headers,      /**< type which defines to hook after all headers have been parsed */
    evhtp_hook_on_path,         /**< type which defines to hook once a path has been parsed */
    evhtp_hook_on_read,         /**< type which defines to hook whenever the parser recieves data in a body */
    evhtp_hook_on_request_fini, /**< type which defines to hook before the request is free'd */
    evhtp_hook_on_connection_fini,
    evhtp_hook_on_new_chunk,
    evhtp_hook_on_chunk_complete,
    evhtp_hook_on_chunks_complete,
    evhtp_hook_on_headers_start,
    evhtp_hook_on_error,        /**< type which defines to hook whenever an error occurs */
    evhtp_hook_on_hostname,
    evhtp_hook_on_write,
    evhtp_hook_on_event,
    evhtp_hook_on_conn_error,   /**< type which defines to hook whenever a connection error occurs */
};

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_glob,
#ifndef EVHTP_DISABLE_REGEX
    evhtp_callback_type_regex,
#endif
};

enum evhtp_proto {
    EVHTP_PROTO_INVALID,
    EVHTP_PROTO_10,
    EVHTP_PROTO_11
};

enum evhtp_type {
    evhtp_type_client,
    evhtp_type_server
};

typedef enum evhtp_hook_type       evhtp_hook_type;
typedef enum evhtp_callback_type   evhtp_callback_type;
typedef enum evhtp_proto           evhtp_proto;
typedef enum evhtp_ssl_scache_type evhtp_ssl_scache_type;
typedef enum evhtp_type            evhtp_type;

typedef void (* evhtp_thread_init_cb)(evhtp_t * htp, evthr_t * thr, void * arg);
typedef void (* evhtp_thread_exit_cb)(evhtp_t * htp, evthr_t * thr, void * arg);
typedef void (* evhtp_callback_cb)(evhtp_request_t * req, void * arg);
typedef void (* evhtp_hook_err_cb)(evhtp_request_t * req, evhtp_error_flags errtype, void * arg);
typedef void (* evhtp_hook_event_cb)(evhtp_connection_t * conn, short events, void * arg);

/* Generic hook for passing ISO tests */
typedef evhtp_res (* evhtp_hook)();

typedef evhtp_res (* evhtp_hook_conn_err_cb)(evhtp_connection_t * connection, evhtp_error_flags errtype, void * arg);
typedef evhtp_res (* evhtp_pre_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (* evhtp_post_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (* evhtp_hook_header_cb)(evhtp_request_t * req, evhtp_header_t * hdr, void * arg);
typedef evhtp_res (* evhtp_hook_headers_cb)(evhtp_request_t * req, evhtp_headers_t * hdr, void * arg);
typedef evhtp_res (* evhtp_hook_path_cb)(evhtp_request_t * req, evhtp_path_t * path, void * arg);
typedef evhtp_res (* evhtp_hook_read_cb)(evhtp_request_t * req, evbuf_t * buf, void * arg);
typedef evhtp_res (* evhtp_hook_request_fini_cb)(evhtp_request_t * req, void * arg);
typedef evhtp_res (* evhtp_hook_connection_fini_cb)(evhtp_connection_t * connection, void * arg);
typedef evhtp_res (* evhtp_hook_chunk_new_cb)(evhtp_request_t * r, uint64_t len, void * arg);
typedef evhtp_res (* evhtp_hook_chunk_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_chunks_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_headers_start_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_hostname_cb)(evhtp_request_t * r, const char * hostname, void * arg);
typedef evhtp_res (* evhtp_hook_write_cb)(evhtp_connection_t * conn, void * arg);

typedef int (* evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);
typedef int (* evhtp_headers_iterator)(evhtp_header_t * header, void * arg);

#ifndef EVHTP_DISABLE_SSL
typedef int (* evhtp_ssl_verify_cb)(int pre_verify, evhtp_x509_store_ctx_t * ctx);
typedef int (* evhtp_ssl_chk_issued_cb)(evhtp_x509_store_ctx_t * ctx, evhtp_x509_t * x, evhtp_x509_t * issuer);
typedef EVP_PKEY * (* evhtp_ssl_decrypt_cb)(char * privfile);

typedef int (* evhtp_ssl_scache_add)(evhtp_connection_t * connection, unsigned char * sid, int sid_len, evhtp_ssl_sess_t * sess);
typedef void (* evhtp_ssl_scache_del)(evhtp_t * htp, unsigned char * sid, int sid_len);
typedef evhtp_ssl_sess_t * (* evhtp_ssl_scache_get)(evhtp_connection_t * connection, unsigned char * sid, int sid_len);
typedef void * (* evhtp_ssl_scache_init)(evhtp_t *);
#endif

struct evhtp_defaults_s {
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
};

struct evhtp_alias_s {
    char * alias;

    TAILQ_ENTRY(evhtp_alias_s) next;
};

/**
 * @ingroup evhtp_core
 * @brief main structure containing all configuration information
 */
struct evhtp_s {
    evhtp_t  * parent;                  /**< only when this is a vhost */
    evbase_t * evbase;                  /**< the initialized event_base */
    evserv_t * server;                  /**< the libevent listener struct */
    char     * server_name;             /**< the name included in Host: responses */
    void     * arg;                     /**< user-defined evhtp_t specific arguments */
    int        bev_flags;               /**< bufferevent flags to use on bufferevent_*_socket_new() */
    uint64_t   max_body_size;
    uint64_t   max_keepalive_requests;

    #define EVHTP_FLAG_ENABLE_100_CONT     (1 << 1)
    #define EVHTP_FLAG_ENABLE_REUSEPORT    (1 << 2)
    #define EVHTP_FLAG_ENABLE_NODELAY      (1 << 3)
    #define EVHTP_FLAG_ENABLE_DEFER_ACCEPT (1 << 4)
    #define EVHTP_FLAG_DEFAULTS            EVHTP_FLAG_ENABLE_100_CONT
    uint16_t flags;             /**< the base flags set for this context, see: EVHTP_FLAG_* */
    uint16_t parser_flags;      /**< default query flags to alter 'strictness' (see EVHTP_PARSE_QUERY_FLAG_*) */

#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_ctx_t * ssl_ctx;  /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg_t * ssl_cfg;
#endif

#ifndef EVHTP_DISABLE_EVTHR
    evthr_pool_t    * thr_pool; /**< connection threadpool */
    pthread_mutex_t * lock;     /**< parent lock for add/del cbs in threads */

    evhtp_thread_init_cb thread_init_cb;
    evhtp_thread_exit_cb thread_exit_cb;

    /* keep backwards compat because I'm dumb and didn't
     * make these structs private
     */
    #define thread_init_cbarg thread_cbarg
    void * thread_cbarg;
#endif
    evhtp_callbacks_t * callbacks;
    evhtp_defaults_t    defaults;

    struct timeval recv_timeo;
    struct timeval send_timeo;

    TAILQ_HEAD(, evhtp_alias_s) aliases;
    TAILQ_HEAD(, evhtp_s) vhosts;
    TAILQ_ENTRY(evhtp_s) next_vhost;
};


/**
 * @brief a generic key/value structure
 */
struct evhtp_kv_s {
    char * key;
    char * val;

    size_t klen;
    size_t vlen;

    char k_heaped; /**< set to 1 if the key can be free()'d */
    char v_heaped; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(evhtp_kv_s) next;
};

TAILQ_HEAD(evhtp_kvs_s, evhtp_kv_s);

/**
 * @brief structure containing a single callback and configuration
 *
 * The definition structure which is used within the evhtp_callbacks_t
 * structure. This holds information about what should execute for either
 * a single or regex path.
 *
 * For example, if you registered a callback to be executed on a request
 * for "/herp/derp", your defined callback will be executed.
 *
 * Optionally you can set callback-specific hooks just like per-connection
 * hooks using the same rules.
 *
 */
struct evhtp_callback_s {
    evhtp_callback_type type;           /**< the type of callback (regex|path) */
    evhtp_callback_cb   cb;             /**< the actual callback function */
    void              * cbarg;          /**< user-defind arguments passed to the cb */
    evhtp_hooks_t     * hooks;          /**< per-callback hooks */
    size_t              len;

    union {
        char * path;
        char * glob;
#ifndef EVHTP_DISABLE_REGEX
        regex_t * regex;
#endif
    } val;

    TAILQ_ENTRY(evhtp_callback_s) next;
};


#endif /* evhtpstructs_h_ */
