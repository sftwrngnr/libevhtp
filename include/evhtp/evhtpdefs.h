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




#ifdef __cplusplus
}
#endif


#endif /* __EVHTPDEFS_H__ */