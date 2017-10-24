/***************************************************/
/* evhtp_test.c                                                        */
/* Unit test for evhtp.c                                            */
/*                                                                            */
/* Written by Dan Henderson                                  */
/* Copyright (C) Critical-stack 2017                        */
/***************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <test_evhtp.h>
#include <evhtp/evhtp.h>
#include <testcasecalls.h>

int testreturn(int rval)
{
    printf("%s\n", RETVALS[rval]);
    return rval;
}

int test_evhtp_request_get_method(void)
{
    htp_method myMethod;
    evhtp_request_t *dummyrq;
    myMethod = evhtp_request_get_method(dummyrq);

}

int test_evhtp_connection_pause(void)
{
    int retval = 0;
    
    return testreturn(retval);    
}

tfuncs testfuncarray[] = {
    {"test_evhtp_request_get_method", test_evhtp_request_get_method},
    {"test_evhtp_connection_pause", test_evhtp_connection_pause},
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

