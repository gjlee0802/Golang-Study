// standard headers
#include <boost/scoped_ptr.hpp>
#include <boost/scoped_array.hpp>
#include <cassert>

// cis headers
#include "x509pkc.h"
#include "charset.h"
#include "base64.h"
#include "cmp_types.h"

#include "pkidb_schema.h"

#include "Exception.hpp"
#include "CMPHelper.hpp"

using namespace Issac;
using namespace std;

namespace Issac
{

int ReasonFlagsToReasonCode(ReasonFlags * const reason)
{
  if (reason == NULL) return CRLReason_unspecified;
  int flag = ::ReasonFlags_Get(const_cast<ReasonFlags *>(reason));

  static int flagToCodeTable[][2] = {
    { ReasonFlags_unused,               CRLReason_unspecified },
    { ReasonFlags_keyCompromise,        CRLReason_keyCompromise },
    { ReasonFlags_cACompromise,         CRLReason_cACompromise },
    { ReasonFlags_affiliationChanged,   CRLReason_affiliationChanged },
    { ReasonFlags_superseded,           CRLReason_superseded },
    { ReasonFlags_cessationOfOperation, CRLReason_cessationOfOperation },
    { ReasonFlags_certificateHold,      CRLReason_certificateHold },
  };

  for (int i = 0; i < signed(sizeof(flagToCodeTable)/sizeof(flagToCodeTable[0]))
    ; i++)
  {
    if ((flag & flagToCodeTable[i][0]) != 0)
    {
      return flagToCodeTable[i][1];
    }
  }
  return CRLReason_unspecified;
}

KeyPolicy *PKIPolicyToKeyPolicy (PKIPolicy *pkiPolicy, bool isRaPolicy)
{
  KeyPolicy *keyPolicy;

  /*# FIXME : 에러 처리 하기 */
  if (pkiPolicy == NULL)
    throw Exception("PKIPolicyToKeyPolicy-> PKIPolicy is null");

  keyPolicy = ASN_New(KeyPolicy, NULL);

  // SID
  ASNOctStr_Set(keyPolicy->identifier,
    pkiPolicy->sid.c_str(), pkiPolicy->sid.size());

  // Name
  // converting string to utf8str
  {
  const char *val = pkiPolicy->name.c_str();
  ASNUTF8Str *utf8 = keyPolicy->name;
  boost::scoped_array<unsigned char> buf(
      new unsigned char[strlen(val) * 2 + 2]);
  int  len;
  ::CHARSET_EuckrToUtf8(buf.get(), &len,
      reinterpret_cast<const unsigned char*>(val));
  ASNUTF8Str_Set(utf8,
      reinterpret_cast<char*>(buf.get()), len);
  }

  // Public Key bit length
  ASNInt_SetInt(keyPolicy->keyBitLength, pkiPolicy->tpublen);
  // Public Key algorithm
  Parameter *param = NULL;
  if (pkiPolicy->pqg.len)
  {
    ASNBuf asnBuf;
    ASNBuf_SetP(&asnBuf, pkiPolicy->pqg.data, pkiPolicy->pqg.len);
    param = ASN_New(Parameter, &asnBuf);
  }
  AlgorithmIdentifier_SetNid(keyPolicy->keyAlgorithm,
      Nid_Sread(pkiPolicy->tpubalg.c_str()), param);
  ASN_Del(param);

  // Validity
  char validity[16];
  sprintf(validity, "%02d/%02d/%02d/%02d",
          pkiPolicy->valdyear, pkiPolicy->valdmon,
          pkiPolicy->valdday,  pkiPolicy->valdhour);
  ASNStr_Set(keyPolicy->validity, validity, 11);
  // LDAP attribute
  if (pkiPolicy->ldapatt[0]) {
    ASNSeq_NewOptional(pASN(&keyPolicy->ldapAttr), ASN_SEQ(keyPolicy));
    ASNStr_Set(keyPolicy->ldapAttr, pkiPolicy->ldapatt.c_str(),
               pkiPolicy->ldapatt.size());
  }

  // Extensions
  ASNBuf asnBuf;
  if (pkiPolicy->plcder.len)
  {
    ASNBuf_SetP(&asnBuf, pkiPolicy->plcder.data,
                pkiPolicy->plcder.len);
    keyPolicy->extensions = ASN_New(Extensions, &asnBuf);
  }

  // RA Issue allowed
  if (isRaPolicy)
    ASNSeq_NewOptional(pASN(&keyPolicy->rAIssuanceAllowed), ASN_SEQ(keyPolicy));

  return keyPolicy;
}

}
