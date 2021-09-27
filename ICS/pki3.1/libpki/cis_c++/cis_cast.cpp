// standard headers
#include <cassert>
#include <sstream>
#include <boost/scoped_array.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>

// cis headers
#include "base64.h"
#include "x509pkc.h"
#include "charset.h"
#include "cmp_types.h"

// pkilib headers
#include "cis_cast.hpp"
#include "Exception.hpp"

namespace Issac
{

using namespace std;

// Oid
template<> Oid string2type(const string& val)
{
  Oid oidVal;
  int ret = ::Oid_Sread(&oidVal, val.c_str());
  if (ret != SUCCESS)
  {
    /*# Throw exception : Invalid format */
    ostringstream ost;
    ost << "string2type: in processing Oid_Sread, value='" << val << "'";
    throw Exception(ost.str().c_str());
  }
  return oidVal;
}

template<> string type2string(Oid const val)
{
  char buf[128];
  ::Oid_SprintEx(buf, const_cast<Oid *>(&val));
  return buf;
}

// ASNInt *
template<> std::string type2string(ASNInt * const val)
{
  char buf[256];
  if (::ASNInt_GetStr(buf, sizeof(buf), const_cast<ASNInt*>(val)) < 0)
    throw Exception("type2string: processing ASNInt_GetStr");

  return buf;
}

// Nid
template<> Nid string2type(const string& val)
{
  Oid oidVal = string2type<Oid>(val);
  return ::Oid_GetNid(&oidVal);
}

template<> string type2string(Nid const val)
{
  Oid oid;
  ::Nid_GetOid(&oid, val);
  assert(oid.len); /*# No throw, cause nid is internal library type */
  return type2string<Oid>(oid);
}

// ASNBuf *
template<> ASNBuf *string2type(const string& val)
{
  ASNBuf *asn = ::ASNBuf_New(val.size());
  int ret = ::Base64_Decode(
    reinterpret_cast<unsigned char *>(asn->data), val.size(),
    reinterpret_cast<unsigned int *>(&asn->len), val.c_str());
  if (ret != 0)
  {
    ASNBuf_Del(asn);
    /*# Throw exception : Invalid format */
    throw Exception("string2type: in processing Base64_Decode");
  }
  return asn;
}

template<> string type2string(ASNBuf * const val)
{
  assert(val);

  int bufMax = val->len*4/3 + 8;
  boost::scoped_array<char> puf(new char[bufMax]);
  ::Base64_Encode(
    puf.get(), bufMax,
    reinterpret_cast<unsigned char *>(val->data), val->len);
  return puf.get();
}

namespace internal
{

// ASNDescriptor를 통한 일반적인 형 변환
template<class T, ASNDescriptor desc>
T* string2asn(const string& val)
{
  T *ret;
  boost::shared_ptr<ASNBuf> buf(string2type<ASNBuf *>(val), ASNBuf_Delete);

  ret = (T*)( (ASN* (*)(ASNDescriptor, ASNBuf*, ASNOption)) \
      ((*(ASNDescriptor *)desc)[0].param) ) \
      (desc, buf.get(), 0);
  // ret = ASN_New(T, buf.get());
  if (ret == NULL)
    throw Exception("string2asn: in processing ASN_New");
  return ret;
}

template<class T>
string asn2string(T * const val)
{
  assert(val);
  boost::shared_ptr<ASNBuf> buf(::ASN_EncodeDER(const_cast<T *>(val)), 
      ASNBuf_Delete);
  if (buf.get() == NULL)
    throw Exception("asn2string: in processing ASN_EncodeDER");
  return type2string<ASNBuf *>(buf.get());
}

} // end of namespace internal

// Cerfigicate *
template<> Certificate *string2type(const string &val)
{
  return internal::string2asn<Certificate, AD_Certificate>(val);
}

template<> string type2string(Certificate * const val)
{
  return internal::asn2string<Certificate>(val);
}

// Extensions *
template<> Extensions *string2type(const string& val)
{
  return internal::string2asn<Extensions, AD_Extensions>(val);
}

template<> string type2string(Extensions * const val)
{
  return internal::asn2string<Extensions>(val);
}

// GeneralName *
template<> GeneralName *string2type(const string& val)
{
  return internal::string2asn<GeneralName, AD_GeneralName>(val);
}

template<> string type2string(GeneralName * const val)
{
  return internal::asn2string<GeneralName>(val);
}

// ASN *
template<> string type2string(ASN * const val)
{
  return internal::asn2string<ASN>(val);
}

// Name *
template<> string type2string(Name * const val)
{
  int ret;
  char buf[1024];
  ret = ::Name_SprintLine(buf, sizeof(buf), (Name *)val);
  if (ret < 0) return "";

  return buf;
}

// ASNUTF8Str *
static void StringToUTF8Str(UTF8String *utf8, const string& val)
{
  assert(utf8);

  /*# FIXME : 효율성을 높이기 위해 UTF8String의 내부 변수를 직접 access하는
              방법도 고려해 볼 것 */
  boost::scoped_array<unsigned char> buf(new unsigned char[val.size() * 2 + 2]);
  
  int  len;
  ::CHARSET_EuckrToUtf8(buf.get(), &len, 
      reinterpret_cast<const unsigned char*>(val.c_str()));

  ASNUTF8Str_Set(utf8, 
      reinterpret_cast<char*>(buf.get()), len);

  return;
}

template<> ASNUTF8Str *string2type(const string& val)
{
  ASNUTF8Str *utf8 = ASN_New(ASNUTF8Str, NULL);
  StringToUTF8Str(utf8, val);
  return utf8;
}

template<> string type2string(ASNUTF8Str * const val)
{
  assert(val);

  /**
   * 여기에서는 memory copy의 회수를 줄이기 위해 UTF8String내의 내부 변수를 직접 
   * 다루고 있으므로, asn1.c의 ASNStr의 내부 구현이 변하는 경우에는 여기에서의 
   * 구현에도 그것이 반영되어야 한다.
   */
  boost::scoped_array<char> ret(new char[val->len + 1]);
  
  int len;
  ::CHARSET_Utf8ToEuckr(
      reinterpret_cast<unsigned char*>(ret.get()), &len,
      reinterpret_cast<unsigned char*>(val->data));

  /*# FIXME : 효율성을 높이기 위해 string의 내부 변수를 직접 access하는
              방법도 고려해 볼 것 */
  return ret.get();
}

} // end of namespace type

