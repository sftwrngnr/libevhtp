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

int simple_test_htp__malloc_(void)
{
    char * mymem = NULL;
    size_t allocsize = 2048;
    int retval = 0; /* Set to success */
    /*mymem = (char *) htp__malloc_(allocsize);*/
    mymem = (char *) malloc(allocsize);
    if (NULL != mymem)
    {
        retval = 1;
        /*htp__free_((void *) mymem); */
        free((void *) mymem);
    }
    return testreturn(retval);
}

int simple_test_htp__calloc_(void)
{
    void *mymem = NULL;
    size_t allocsize = 1024;
    size_t numblocks = 2;
    int retval = 0;
    
    mymem = calloc(numblocks, allocsize);
    if (mymem != NULL)
    {
        retval = 0; /* Test fail mode */
        free(mymem);
    }
    
    return testreturn(retval);    
}

tfuncs testfuncarray[] = {
    {"simple_test_htp__malloc_", simple_test_htp__malloc_},
    {"simple_test_htp__calloc_", simple_test_htp__calloc_},
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

