#ifndef __EVHTPDEFS_H__
#define __EVHTPDEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define EVHTP_VERSION           "2.0.0"
#define EVHTP_VERSION_MAJOR     2
#define EVHTP_VERSION_MINOR     0
#define EVHTP_VERSION_PATCH     0

#define evhtp_headers_iterator  evhtp_kvs_iterator

#define EVHTP_RES_ERROR         0
#define EVHTP_RES_PAUSE         1
#define EVHTP_RES_FATAL         2
#define EVHTP_RES_USER          3
#define EVHTP_RES_DATA_TOO_LONG 4
#define EVHTP_RES_OK            200

#ifndef DOXYGEN_SHOULD_SKIP_THIS
#define EVHTP_RES_100           100
#define EVHTP_RES_CONTINUE      100
#define EVHTP_RES_SWITCH_PROTO  101
#define EVHTP_RES_PROCESSING    102
#define EVHTP_RES_URI_TOOLONG   122

#define EVHTP_RES_200           200
#define EVHTP_RES_CREATED       201
#define EVHTP_RES_ACCEPTED      202
#define EVHTP_RES_NAUTHINFO     203
#define EVHTP_RES_NOCONTENT     204
#define EVHTP_RES_RSTCONTENT    205
#define EVHTP_RES_PARTIAL       206
#define EVHTP_RES_MSTATUS       207
#define EVHTP_RES_IMUSED        226

#define EVHTP_RES_300           300
#define EVHTP_RES_MCHOICE       300
#define EVHTP_RES_MOVEDPERM     301
#define EVHTP_RES_FOUND         302
#define EVHTP_RES_SEEOTHER      303
#define EVHTP_RES_NOTMOD        304
#define EVHTP_RES_USEPROXY      305
#define EVHTP_RES_SWITCHPROXY   306
#define EVHTP_RES_TMPREDIR      307

#define EVHTP_RES_400           400
#define EVHTP_RES_BADREQ        400
#define EVHTP_RES_UNAUTH        401
#define EVHTP_RES_PAYREQ        402
#define EVHTP_RES_FORBIDDEN     403
#define EVHTP_RES_NOTFOUND      404
#define EVHTP_RES_METHNALLOWED  405
#define EVHTP_RES_NACCEPTABLE   406
#define EVHTP_RES_PROXYAUTHREQ  407
#define EVHTP_RES_TIMEOUT       408
#define EVHTP_RES_CONFLICT      409
#define EVHTP_RES_GONE          410
#define EVHTP_RES_LENREQ        411
#define EVHTP_RES_PRECONDFAIL   412
#define EVHTP_RES_ENTOOLARGE    413
#define EVHTP_RES_URITOOLARGE   414
#define EVHTP_RES_UNSUPPORTED   415
#define EVHTP_RES_RANGENOTSC    416
#define EVHTP_RES_EXPECTFAIL    417
#define EVHTP_RES_IAMATEAPOT    418

#define EVHTP_RES_500           500
#define EVHTP_RES_SERVERR       500
#define EVHTP_RES_NOTIMPL       501
#define EVHTP_RES_BADGATEWAY    502
#define EVHTP_RES_SERVUNAVAIL   503
#define EVHTP_RES_GWTIMEOUT     504
#define EVHTP_RES_VERNSUPPORT   505
#define EVHTP_RES_BWEXEED       509
#endif

struct evhtp_callback_s;
struct evhtp_callbacks_s;

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



#ifdef __cplusplus
}
#endif


#endif /* __EVHTPDEFS_H__ */