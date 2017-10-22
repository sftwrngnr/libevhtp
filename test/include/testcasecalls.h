/********************************************/
/* testcasecalls.h                                          */
/* Contains structures for calling test cases */
/* easily.                                                       */
/********************************************/
#ifndef testcasecalls_h
#define testcasecalls_h

const char * RETVALS[] = {"FAIL", "SUCCESS"};

typedef int (*funcptr)(void);

typedef struct testfuncs
{
    char *testname;
    void *mytestfunc;
} tfuncs;

#endif /* testcasecalls_h */
