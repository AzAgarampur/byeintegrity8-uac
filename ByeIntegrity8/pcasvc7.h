
/*
* I HAVE EDITED THIS FILE BY HAND IN ORDER TO MAKE THIS WORK
* THIS IS NOT THE PURE OUTPUT OF MIDL.EXE
*
* IF YOU ARE COMPILING THE IDL YOURSELF YOU MUST EDIT THE PROCEDURE
* NUMBER IN THIS GENERATED FILE IN ORDER FOR THE CALL TO WORK
*/

 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 19:14:07 2038
 */
/* Compiler settings for pcasvc7.idl, pcasvc7.acf:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __pcasvc7_h__
#define __pcasvc7_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __PcaService_INTERFACE_DEFINED__
#define __PcaService_INTERFACE_DEFINED__

/* interface PcaService */
/* [explicit_handle][version][uuid] */ 

long RAiNotifyUserCallbackExceptionProcess( 
    handle_t bindingHandle, // binding handle
    /* [string][in] */ wchar_t *exePathName, // full exe path name
    /* [in] */ long unknown0, // always 1
    /* [in] */ long processId); // process ID to use



extern RPC_IF_HANDLE PcaService_v1_0_c_ifspec;
extern RPC_IF_HANDLE PcaService_v1_0_s_ifspec;
#endif /* __PcaService_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


