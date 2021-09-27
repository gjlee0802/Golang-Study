/**
 * @file     cis_cast.hpp
 *
 * @desc     cis type간의 전환 등의 작업을 위해 필요한 class 들 선언
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.10.30
 *
 * Revision  History
 *
 * @date     2003.04.30 : Start
 *
 * @modify   조현래(hrcho@pentasecurity.com)
 * @date     2005.05.15 : 박지영의 코드를 기반으로 Start
 *
 */

#ifndef ISSAC_CIS_CAST_HPP
#define ISSAC_CIS_CAST_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#ifndef _STRING_INCLUDED_
#include <string>
#define _STRING_INCLUDED_
#endif

#include "type_cast.hpp"

// forward declarations for cis
struct tm;
typedef struct _Oid Oid;
typedef unsigned int Nid;
typedef struct _ASNBuf ASNBuf;
typedef struct _ASNClass ASNClass;
typedef ASNClass ASN;
typedef struct _ASNInt ASNInt;
typedef struct _Certificate Certificate;
typedef struct _Extensions Extensions;
typedef struct _GeneralName GeneralName;
typedef struct _Name Name;
typedef struct _ASNBitStr ASNBitStr;
typedef struct _ASNStr ASNStr;
typedef ASNStr ASNUTF8Str;

namespace Issac {

// Oid
template<> Oid string2type(const std::string &val);
template<> std::string type2string(Oid const val);

// ASNInt *
template<> std::string type2string(ASNInt * const val);

/**
 * @note : Nid는 unsigned int 로 typedef 되어 있기 때문에, unsigned int type도 
 *         Nid와 같은 방법으로 compiler에서 해석하게 된다. 따라서, 
 *         unsigned int type은 이 방식으로는 사용해서는 안된다.
 */
// Nid
template<> Nid string2type(const std::string &val);
template<> std::string type2string(Nid const val);

// ASNBuf *
// returned value must be 'ASNBuf_Del'ed
template<> ASNBuf *string2type(const std::string &val); 
template<> std::string type2string(ASNBuf * const val);

// Cerfigicate *
// returned value must be 'ASN_Del'ed
template<> Certificate* string2type(const std::string &val);
template<> std::string type2string(Certificate * const val);

// Extensions *
template<> Extensions* string2type(const std::string &val);
template<> std::string type2string(Extensions * const val);

// GeneralName *
template<> GeneralName* string2type(const std::string &val);
template<> std::string type2string(GeneralName * const val);

// ASN *
template<> std::string type2string(ASN * const val);
// std::string에서 ASN Type으로의 전환은 지원하지 않는다.

// Name *
/**
 * 주어진 Name값을 Name_SprintLine함수를 이용하여 전환된 문자열을 return 한다.
 * Name_SprintLine에 실패하거나 NULL값이 입력으로 주어진 경우에는 
 * 빈 문자열을 return 한다.
 *
 * @param *val (In) Name 값
 * @return
 *  - 주어진 Name값을 Name_SprintLine 한 값
 */
template<> std::string type2string(Name * const val);


// ASNUTF8Str
/**
 * EUC-KR 형식의 문자열을 UTF8String으로 전환한다.
 * 단 return값은 내부적으로 메모리가 할당되므로 반드시 free해 주어야 한다.
 */
template<> ASNUTF8Str* string2type(const std::string &val);
/**
 * UTF8String을 EUC-KR 형식의 문자열로 전환한다.
 */
template<> std::string type2string(ASNUTF8Str * const val);

// ReasonFlags *
/**
 * 주어진 reason flag에 해당하는 reason code 값을 return 한다.
 * 단, reason flag에 복수개의 reason이 설정되어 있는 경우에는 그 중에서
 * 가장 작은 reason code 값을 리턴한다.
 *
 * @param *rf (In) Reason Flag 값(NULL이면 unspecified reason code를 리턴)
 * @return
 *    - 주어진 reason flag에 해당하는 reason code
 */

} // end of namespace

#endif

