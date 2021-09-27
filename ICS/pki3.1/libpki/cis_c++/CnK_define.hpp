// CnK_define.hpp: 인증서와 공개키 관련 정의
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_CNK_DEFINE_HPP_
#define ISSAC_CNK_DEFINE_HPP_

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef _LIST_INCLUDED_
#include <list>
#define _LIST_INCLUDED_
#endif
#include <utility>
#include <string>
#include <vector>

#ifndef BOOST_SHARED_PTR_HPP_INCLUDED
#include <boost/shared_ptr.hpp>
#define BOOST_SHARED_PTR_HPP_INCLUDED
#endif

#include "cert.h"

// forward declarations for cis
typedef struct _PrivateKeyInfo PrivateKeyInfo;

namespace Issac 
{

typedef boost::shared_ptr<Certificate> CertSharedPtr;
typedef std::list<CertSharedPtr> CertSharedPtrs;

typedef boost::shared_ptr<PrivateKeyInfo> PrivateKeyInfoSharedPtr;
typedef std::pair<CertSharedPtr, PrivateKeyInfoSharedPtr> CnKSharedPtr;
typedef std::list<CnKSharedPtr> CnKSharedPtrs;

}


#endif // ISSAC_CNK_DEFINE_HPP_
