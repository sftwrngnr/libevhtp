/***
 * evhtp_client.c
 * @brief libevhtp client functions. Pulled out from evhtp.c for refactoring.
 *
 * @author Dan Henderson
 *
 ***/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <inttypes.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef NO_SYS_UN
#include <sys/un.h>
#endif

#include <limits.h>
#include <event2/dns.h>

#include <evhtp/evhtp.h>
#include <internal.h>
#include <log.h>

/*****************************************************************
* client request functions                                      *
*****************************************************************/

/** Static functions **/

static const char *
status_code_to_str(evhtp_res code)
{
    switch (code) {
        case EVHTP_RES_200:
            return "OK";
        case EVHTP_RES_300:
            return "Redirect";
        case EVHTP_RES_400:
            return "Bad Request";
        case EVHTP_RES_NOTFOUND:
            return "Not Found";
        case EVHTP_RES_SERVERR:
            return "Internal Server Error";
        case EVHTP_RES_CONTINUE:
            return "Continue";
        case EVHTP_RES_FORBIDDEN:
            return "Forbidden";
        case EVHTP_RES_SWITCH_PROTO:
            return "Switching Protocols";
        case EVHTP_RES_MOVEDPERM:
            return "Moved Permanently";
        case EVHTP_RES_PROCESSING:
            return "Processing";
        case EVHTP_RES_URI_TOOLONG:
            return "URI Too Long";
        case EVHTP_RES_CREATED:
            return "Created";
        case EVHTP_RES_ACCEPTED:
            return "Accepted";
        case EVHTP_RES_NAUTHINFO:
            return "No Auth Info";
        case EVHTP_RES_NOCONTENT:
            return "No Content";
        case EVHTP_RES_RSTCONTENT:
            return "Reset Content";
        case EVHTP_RES_PARTIAL:
            return "Partial Content";
        case EVHTP_RES_MSTATUS:
            return "Multi-Status";
        case EVHTP_RES_IMUSED:
            return "IM Used";
        case EVHTP_RES_FOUND:
            return "Found";
        case EVHTP_RES_SEEOTHER:
            return "See Other";
        case EVHTP_RES_NOTMOD:
            return "Not Modified";
        case EVHTP_RES_USEPROXY:
            return "Use Proxy";
        case EVHTP_RES_SWITCHPROXY:
            return "Switch Proxy";
        case EVHTP_RES_TMPREDIR:
            return "Temporary Redirect";
        case EVHTP_RES_UNAUTH:
            return "Unauthorized";
        case EVHTP_RES_PAYREQ:
            return "Payment Required";
        case EVHTP_RES_METHNALLOWED:
            return "Not Allowed";
        case EVHTP_RES_NACCEPTABLE:
            return "Not Acceptable";
        case EVHTP_RES_PROXYAUTHREQ:
            return "Proxy Authentication Required";
        case EVHTP_RES_TIMEOUT:
            return "Request Timeout";
        case EVHTP_RES_CONFLICT:
            return "Conflict";
        case EVHTP_RES_GONE:
            return "Gone";
        case EVHTP_RES_LENREQ:
            return "Length Required";
        case EVHTP_RES_PRECONDFAIL:
            return "Precondition Failed";
        case EVHTP_RES_ENTOOLARGE:
            return "Entity Too Large";
        case EVHTP_RES_URITOOLARGE:
            return "Request-URI Too Long";
        case EVHTP_RES_UNSUPPORTED:
            return "Unsupported Media Type";
        case EVHTP_RES_RANGENOTSC:
            return "Requested Range Not Satisfiable";
        case EVHTP_RES_EXPECTFAIL:
            return "Expectation Failed";
        case EVHTP_RES_IAMATEAPOT:
            return "I'm a teapot";
        case EVHTP_RES_NOTIMPL:
            return "Not Implemented";
        case EVHTP_RES_BADGATEWAY:
            return "Bad Gateway";
        case EVHTP_RES_SERVUNAVAIL:
            return "Service Unavailable";
        case EVHTP_RES_GWTIMEOUT:
            return "Gateway Timeout";
        case EVHTP_RES_VERNSUPPORT:
            return "HTTP Version Not Supported";
        case EVHTP_RES_BWEXEED:
            return "Bandwidth Limit Exceeded";
    } /* switch */

    return "UNKNOWN";
}     /* status_code_to_str */

static int
htp__create_headers_(evhtp_header_t * header, void * arg)
{
    struct evbuffer * buf = arg;

    evbuffer_expand(buf, header->klen + 2 + header->vlen + 2);
    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);

    return 0;
}

static struct evbuffer *
htp__create_reply_(evhtp_request_t * request, evhtp_res code)
{
    struct evbuffer * buf;
    const char      * content_type;
    char              res_buf[2048];
    int               sres;
    size_t            out_len;
    unsigned char     major;
    unsigned char     minor;
    char              out_buf[64];

    evhtp_assert(request
                 && request->headers_out
                 && request->buffer_out
                 && request->conn
                 && request->rc_parser);

    content_type = evhtp_header_find(request->headers_out, "Content-Type");
    out_len      = evbuffer_get_length(request->buffer_out);

    if ((buf = request->rc_scratch) == NULL)
    {
        request->rc_scratch = evbuffer_new();
        evhtp_alloc_assert(request->rc_scratch);
    }

    evbuffer_drain(buf, -1);

    if (htparser_get_multipart(request->rc_parser) == 1)
    {
        goto check_proto;
    }

    if (out_len && !(request->flags & EVHTP_REQ_FLAG_CHUNKED))
    {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_header_find(request->headers_out, "Content-Length"))
        {
            /* convert the buffer_out length to a string and set
             * and add the new Content-Length header.
             */
            evhtp_modp_sizetoa(out_len, out_buf);

            evhtp_headers_add_header(request->headers_out,
                                     evhtp_header_new("Content-Length", out_buf, 0, 1));
        }
    }
check_proto:
    /* add the proper keep-alive type headers based on http version */
    switch (request->proto) {
        case EVHTP_PROTO_11:
            if (!(request->flags & EVHTP_REQ_FLAG_KEEPALIVE))
            {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "close", 0, 0));
            }

            if (!evhtp_header_find(request->headers_out, "Content-Length"))
            {
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Content-Length", "0", 0, 0));
            }

            break;
        case EVHTP_PROTO_10:
            if (request->flags & EVHTP_REQ_FLAG_KEEPALIVE)
            {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            /* this sometimes happens when a response is made but paused before
             * the method has been parsed */
            htparser_set_major(request->rc_parser, 1);
            htparser_set_minor(request->rc_parser, 0);
            break;
    } /* switch */


    if (!content_type)
    {
        evhtp_headers_add_header(request->headers_out,
                                 evhtp_header_new("Content-Type", "text/plain", 0, 0));
    }

    /* attempt to add the status line into a temporary buffer and then use
     * evbuffer_add(). Using plain old snprintf() will be faster than
     * evbuffer_add_printf(). If the snprintf() fails, which it rarely should,
     * we fallback to using evbuffer_add_printf().
     */

    major = evhtp_modp_uchartoa(htparser_get_major(request->rc_parser));
    minor = evhtp_modp_uchartoa(htparser_get_minor(request->rc_parser));

    evhtp_modp_u32toa((uint32_t)code, out_buf);

    sres  = snprintf(res_buf, sizeof(res_buf), "HTTP/%c.%c %s %s\r\n",
                     major, minor, out_buf, status_code_to_str(code));

    if (sres >= sizeof(res_buf) || sres < 0)
    {
        /* failed to fit the whole thing in the res_buf, so just fallback to
         * using evbuffer_add_printf().
         */
        evbuffer_add_printf(buf, "HTTP/%c.%c %d %s\r\n",
                            major, minor,
                            code, status_code_to_str(code));
    } else {
        /* copy the res_buf using evbuffer_add() instead of add_printf() */
        evbuffer_add(buf, res_buf, sres);
    }


    evhtp_headers_for_each(request->headers_out, htp__create_headers_, buf);
    evbuffer_add(buf, "\r\n", 2);

    if (evbuffer_get_length(request->buffer_out))
    {
        evbuffer_add_buffer(buf, request->buffer_out);
    }

    return buf;
}     /* htp__create_reply_ */


/**
 * @brief Creates a new evhtp_request_t
 *
 * @param c
 *
 * @return evhtp_request_t structure on success, otherwise NULL
 */
static evhtp_request_t *
htp__request_new_(evhtp_connection_t * c)
{
    evhtp_request_t * req;
    uint8_t           error;

    if (evhtp_unlikely(!(req = htp__calloc(sizeof(*req), 1))))
    {
        return NULL;
    }

    error       = 1;
    req->conn   = c;
    req->htp    = c ? c->htp : NULL;
    req->status = EVHTP_RES_OK;

    do {
        if (evhtp_unlikely(!(req->buffer_in = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->buffer_out = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_in = htp__malloc(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_out = htp__malloc(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        TAILQ_INIT(req->headers_in);
        TAILQ_INIT(req->headers_out);

        error = 0;
    } while (0);

    if (error == 0)
    {
        return req;
    }

    evhtp_safe_free(req, htp__request_free_);

    return req;
} /* htp__request_new_ */

static int
htp__request_parse_start_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (evhtp_unlikely(c->type == evhtp_type_client))
    {
        return 0;
    }

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        return -1;
    }

    if (c->request)
    {
        if (c->request->flags & EVHTP_REQ_FLAG_FINISHED)
        {
            htp__request_free_(c->request);
        } else {
            return -1;
        }
    }

    if (((c->request = htp__request_new_(c))) == NULL)
    {
        return -1;
    }

    return 0;
}


/** Public functions **/

evhtp_connection_t *
evhtp_connection_new(struct event_base * evbase, const char * addr, uint16_t port)
{
    return evhtp_connection_new_dns(evbase, NULL, addr, port);
}

evhtp_connection_t *
evhtp_connection_new_dns(struct event_base * evbase, struct evdns_base * dns_base,
                         const char * addr, uint16_t port)
{
    evhtp_connection_t * conn;
    int                  err;

    log_debug("Enter");
    evhtp_assert(evbase != NULL);

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client)))
    {
        return NULL;
    }

    conn->evbase = evbase;
    conn->bev    = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    if (conn->bev == NULL)
    {
        evhtp_connection_free(conn);

        return NULL;
    }

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, NULL, NULL,
                      htp__connection_eventcb_, conn);

    if (dns_base != NULL)
    {
        err = bufferevent_socket_connect_hostname(conn->bev, dns_base,
                                                  AF_UNSPEC, addr, port);
    } else {
        struct sockaddr_in  sin4;
        struct sockaddr_in6 sin6;
        struct sockaddr   * sin;
        int                 salen;

        if (inet_pton(AF_INET, addr, &sin4.sin_addr))
        {
            sin4.sin_family = AF_INET;
            sin4.sin_port   = htons(port);
            sin = (struct sockaddr *)&sin4;
            salen           = sizeof(sin4);
        } else if (inet_pton(AF_INET6, addr, &sin6.sin6_addr))
        {
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port   = htons(port);
            sin = (struct sockaddr *)&sin6;
            salen = sizeof(sin6);
        } else {
            /* Not a valid IP. */
            evhtp_connection_free(conn);

            return NULL;
        }

        err = bufferevent_socket_connect(conn->bev, sin, salen);
    }

    /* not needed since any of the bufferevent errors will go straight to
     * the eventcb
     */
    if (err)
    {
        return NULL;
    }

    return conn;
}     /* evhtp_connection_new_dns */

#ifndef EVHTP_DISABLE_SSL
evhtp_connection_t *
evhtp_connection_ssl_new(struct event_base * evbase,
                         const char        * addr,
                         uint16_t            port,
                         evhtp_ssl_ctx_t   * ctx)
{
    evhtp_connection_t * conn;
    struct sockaddr_in   sin;
    int                  rc;

    if (evbase == NULL)
    {
        return NULL;
    }

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client)))
    {
        return NULL;
    }

    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr(addr);
    sin.sin_port        = htons(port);

    conn->ssl           = SSL_new(ctx);
    evhtp_assert(conn->ssl != NULL);

    conn->evbase        = evbase;
    conn->bev           = bufferevent_openssl_socket_new(
        evbase, -1,
        conn->ssl,
        BUFFEREVENT_SSL_CONNECTING,
        BEV_OPT_CLOSE_ON_FREE);

    evhtp_assert(conn->bev != NULL);

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, NULL, NULL,
                      htp__connection_eventcb_, conn);

    rc = bufferevent_socket_connect(conn->bev,
                                    (struct sockaddr *)&sin, sizeof(sin));

    evhtp_assert(rc == 0);

    return conn;
}     /* evhtp_connection_ssl_new */

#endif


evhtp_request_t *
evhtp_request_new(evhtp_callback_cb cb, void * arg)
{
    evhtp_request_t * r;

    r        = htp__request_new_(NULL);
    evhtp_alloc_assert(r);

    r->cb    = cb;
    r->cbarg = arg;
    r->proto = EVHTP_PROTO_11;

    return r;
}

int
evhtp_make_request(evhtp_connection_t * c, evhtp_request_t * r,
                   htp_method meth, const char * uri)
{
    struct evbuffer * obuf;
    char            * proto;

    obuf       = bufferevent_get_output(c->bev);
    r->conn    = c;
    c->request = r;

    switch (r->proto) {
        case EVHTP_PROTO_10:
            proto = "1.0";
            break;
        case EVHTP_PROTO_11:
        default:
            proto = "1.1";
            break;
    }

    evbuffer_add_printf(obuf, "%s %s HTTP/%s\r\n",
                        htparser_get_methodstr_m(meth), uri, proto);

    evhtp_headers_for_each(r->headers_out, htp__create_headers_, obuf);
    evbuffer_add_reference(obuf, "\r\n", 2, NULL, NULL);

    if (evbuffer_get_length(r->buffer_out))
    {
        evbuffer_add_buffer(obuf, r->buffer_out);
    }

    return 0;
}

unsigned int
evhtp_request_status(evhtp_request_t * r)
{
    return htparser_get_status(r->conn->parser);
}

