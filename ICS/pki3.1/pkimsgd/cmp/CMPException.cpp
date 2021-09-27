// CMP.cpp: implementation of the CMP class.
//
////////////////////////////////////////////////////////////////////////////////

// standard headers
#include <boost/scoped_ptr.hpp>
#include <cassert>

// cis headers
#include "asn1.h"
#include "cmp.h"
#include "charset.h"
#include "pkimessage.h"

// pki headers
#include "Trace.h"

#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"
#include "CMPErrorMsgTable.hpp"

using namespace std;

namespace Issac
{

//  CMPException
//
//////////////////////////////////////////////////////

CMPException::CMPException(int code) : LogException(code) {}

void CMPException::setErrorMsgContent(int status,
                                      const std::string &freeText,
                                      int failInfo,
                                      int errCode,
                                      const std::string &errDetail)
{
  _errMsg.reset(ASN_New(ErrorMsgContent, NULL), ASN_Delete);

  ::PKIStatusInfo_Set(_errMsg->pKIStatusInfo, status, freeText.c_str(),
    failInfo);
  if (errCode != 0)
  {
    ASNSeq_NewOptional(pASN(&_errMsg->errorCode), ASN_SEQ(_errMsg.get()));
    ASNInt_SetInt(_errMsg->errorCode, errCode);
  }

  if (!errDetail.empty())
  {
    ASNSeq_NewOptional(pASN(&_errMsg->errorDetails), ASN_SEQ(_errMsg.get()));
    UTF8String *utf8Str = ASN_New(UTF8String, NULL);
    unsigned char *utfText = new unsigned char[errDetail.size() * 2 + 2];
    int utfTextLen;
    ::CHARSET_EuckrToUtf8(
      utfText, &utfTextLen,
      reinterpret_cast<unsigned char *>(const_cast<char *>(errDetail.c_str())));
    ASNUTF8Str_Set(utf8Str, reinterpret_cast<char*>(utfText), utfTextLen);
    delete[] utfText;
    ASNSeqOf_AddP(ASN_SEQOF(_errMsg->errorDetails), ASN(utf8Str));
  }
}

ErrorMsgContent *CMPException::getErrorMsgContent() const
{
  return _errMsg.get();
}

CMPSendErrorException::CMPSendErrorException(int code)
  : CMPException(code)
{
  CMP_ERROR_MSG_TABLE_ITEM item = CMPErrorMsgTable::get()->getItem(code);

  if (item.status.empty())
    item.status = item.errorDetail;

  if (item.logCode != LOG_TABLE_INVALID_CODE)
  {
    setErrorMsgContent(
      PKIStatus_rejection,
      item.status,
      item.failInfo,
      item.errorCode,
      item.errorDetail);
  }
}

}

