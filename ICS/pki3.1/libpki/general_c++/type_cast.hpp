/**
 * @file     type_cast.hpp
 *
 * @desc     자주 쓰는 type간의 전환 등의 작업을 위해 필요한 class 들 선언
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.10.30
 *
 * Revision  History
 *
 * @date     2003.04.30 : Start
 *
 * @modify   조현래(hrcho@pentasecurity.com)
 * @date     2005.05.15 : 박지영의 클래스 기반의 코드를 기반으로 Start
 *
 */

#ifndef ISSAC_TYPE_CAST_HPP
#define ISSAC_TYPE_CAST_HPP

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
#include <sstream>

#include <boost/static_assert.hpp>

// forward declarations for cis
struct tm;

namespace Issac {

// 일반적인 로직이 존재하지 않으므로 템플릿을 두지 않고 인자의 타입이 다른
// 동일한 이름의 함수를 각각 구현하는 것이 합당하지만,
// 호출자가 명시적으로 타입을 선택하게 하여 혼동을 막기 위해서 템플릿 함수로
// 구현했다.
// 클래스 템플릿으로 구현하는 것도 생각해 볼 만하지만, cis_cast<ASN*>::get(str)
// 과 같은 식의 static 함수 호출이 아니라 static_cast<ASN*>(str)와 같은 
// 캐스트 연산자의 흉내를 내고 싶었는데, 이것을 클래스 템플릿으로 내려면 문제가 
// 있다. 내 생각으로는 이것을 위해서는 operator ASN*()과 같은 식의 연산자가 
// 임시 객체에 호출되는 메커니즘을 이용할 수 밖에 없는데 (혹시 더 좋은 방법이 
// 있으면 hrcho@pentasecurity.com에 알려 주길 바란다.) 사용자가 직접 캐스트 
// 객체의 인스턴스를 생성하는 코드를 작성하는 등 혼돈을 줄 수가 있다.
// 그래서 결국 함수 템플릿으로 구현했다. 하지만 이 라이브러리의 사용자는 
// 타입명시 없이 직접 호출하지 말고, 타입을 명시하고 호출하기 바란다.
// 나쁜 코드: ASN *a = ...; std::string s = type2string(a)
// 좋은 코드: ASN *a = ...; std::string s = type2string<ASN*>(a)

// 아래의 템플릿은 반드시 타입별로 specialization을 통해서 구현되어야 한다.
// 만약 그렇지 않으면 char a[-1]; 이 생성되어 컴파일 오류를 낸다.
template<typename _T> std::string type2string(_T const val)
{
  //assert(false); 
  return std::string("");
}
template<typename _T> _T string2type(const std::string& val)
{
  //assert(false);

  _T dummy;
  return dummy;
}
// 위의 템프릿에 대한 다양한 cis type별 구현은 ../cis_c++/cis_cast에...
// scalar 타입은 표준 스트림이나 boost::lexical_cast를 사용하라

template<> std::string type2string(std::string const val);
template<> std::string string2type(const std::string& val);

template<> std::string type2string(int const val);
template<> int string2type(const std::string& val);

template<> std::string type2string(char * const val);

// 복수의 인자
template<typename _T> std::string type2string(_T const val, 
    const std::string &format) { /*assert(false);*/ return std::string("");}
template<typename _T> _T string2type(const std::string& val, 
    const std::string &format) { /*assert(false);*/ _T dummy; return dummy;}
// struct tm, time_t
/** 
 * 문자열로 되어 있는 시간 값을 struct tm으로 전환
 *
 * format 다음과 같은 형식을 갖는다.
 *  - yyyy : 4자리 년도
 *  - mm   : 월
 *  - dd   : 일
 *  - HH24 : 시간(24시간)
 *  - MI   : 분
 *  - SS   : 초

 * 기본 시간 문자열 형식("yyyymmdd HH24:MI:SS")
 */
extern const char *const DEFAULT_TIME_FORMAT;
extern const char *const YEAR;
extern const char *const MONTH;
extern const char *const MDAY;
extern const char *const HOUR;
extern const char *const MIN;
extern const char *const SECOND;

template<> struct std::tm string2type(const std::string &val, 
    const std::string &format);
template<> struct std::tm string2type(const std::string &val);
template<> std::string type2string(struct tm const val, 
    const std::string &format);
template<> std::string type2string(struct tm const val);

// time_t 는 long 혹은 int라 절대 쓰지말고 struct tm을 이용하라
//template<> time_t string2type(std::string &val, const std::string &format);
//template<> time_t string2type(std::string &val);
//template<> std::string type2string(time_t const val, const std::string &format);
//template<> std::string type2string(time_t const val);

} // end of namespace

#endif

