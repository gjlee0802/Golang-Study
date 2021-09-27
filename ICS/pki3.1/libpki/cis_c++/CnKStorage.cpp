// pki_cnk_storage.cpp: implementation of the pki_cnk_storage class.
//
//////////////////////////////////////////////////////////////////////

#ifdef WIN32
#pragma warning(disable:4786)
#endif
#ifdef WIN32
#include <windows.h>
#endif

// standard headers
#include <sstream>
#include <vector>

// cis headers
#include "pkimessage.h"

// libpki headers
#include "CertHelper.h"
#include "PrivateKeyShare.h"
#include "KeyHistory.h"
#include "CnKStorage.hpp"
#include "Exception.hpp"

namespace Issac
{

using namespace std;

CnKSharedPtrs CnKStorage::loadCnKs(std::vector< pair<std::string, std::string> > id_passwds, 
                                   std::string certFile, std::string prikeyFile, 
                                   std::string keyhistFile)
{
  _certFile = certFile;
  _prikeyFile = prikeyFile;
  _keyhistFile = keyhistFile;
  _id_passwds = id_passwds;

  CertSharedPtr cert;
  PrivateKeyInfoSharedPtr prikey;

  cert = CertSharedPtr(CERT_NewFromFile(_certFile.c_str()), ASN_Delete);

  if (cert.get() == NULL)
    throw Exception(ER_S_CNK_STORAGE_FAIL_TO_LOAD_CERT);

  prikey = _loadPrivateKey();

  CnKSharedPtrs cnks;
  cnks.push_back(CnKSharedPtr(cert, prikey));

  // 3. 기존 인증서/비공개키 가져오기
  _loadPrevCnKs(cnks);

  return cnks;
}

PrivateKeyInfoSharedPtr CnKStorage::_loadPrivateKey()
{
  int ret, reqNum = 0;
  PrivateKeyInfo *prikey;
  boost::shared_ptr<PrivateKeyInfo> prikeySharedPtr;

  ::KEYSHARE_GetReqInfosNum(&reqNum, _prikeyFile.c_str());

  EncryptedPrivateKey *encprikey;
  ASNBuf *bufEncprikey;

  bufEncprikey = ASNBuf_NewFromFile(_prikeyFile.c_str());
  if (bufEncprikey == NULL)
    throw Exception(ER_S_CNK_STORAGE_FAIL_TO_LOAD_CERT);

  encprikey = ASN_New(EncryptedPrivateKey, bufEncprikey);
  ASNBuf_Del(bufEncprikey);
  if (encprikey == NULL)
    throw Exception(ER_S_CNK_STORAGE_FAIL_TO_LOAD_CERT);

  if ((signed)_id_passwds.size() < reqNum)
    throw Exception(ER_S_CNK_STORAGE_NEED_MORE_ID_PASSWDS);

  char *ids[10];
  char *passwds[10];
  for (int i = 0; i < reqNum; i++)
  {
    ids[i] = (char *)_id_passwds[i].first.c_str();
    passwds[i] = (char *)_id_passwds[i].second.c_str();
  }
  ret = KEYSHARE_RecoverPrivateKey(&prikey, encprikey, NULL, 
    const_cast<const char**>(static_cast<char**>(ids)), 
    const_cast<const char**>(static_cast<char**>(passwds)), reqNum);
  ASN_Del(encprikey);

  if (ret != SUCCESS)
    throw Exception(ER_S_CNK_STORAGE_FAIL_TO_DECRYPT_PRIKEY);

  prikeySharedPtr = PrivateKeyInfoSharedPtr(prikey, ASN_Delete);

  return prikeySharedPtr;
}

void CnKStorage::_loadPrevCnKs(CnKSharedPtrs &cnks)
{
  if (access(_keyhistFile.c_str(), 0) != 0)
    return;

  int ret;
  Certificate *prevCert;
  PrivateKeyInfo *prevprikey;

  CnKSharedPtr cnk = *cnks.begin();

  do
  {
    prevCert = NULL;
    prevprikey = NULL;
    ret = ::KEYHIST_LoadPrevCertificate(&prevCert,
      NULL, NULL, cnk.first.get(), _keyhistFile.c_str());

    if (ret == SUCCESS)
    {
      ret = ::KEYHIST_LoadPrevPrivateKey(&prevprikey,
        cnk.first.get(), cnk.second.get(), _keyhistFile.c_str());
    }

    if (ret == SUCCESS)
    {
      cnk = CnKSharedPtr(boost::shared_ptr<Certificate>(prevCert), 
        boost::shared_ptr<PrivateKeyInfo>(prevprikey));
      cnks.push_back(cnk);
    }
    else
    {
      ASN_Del(prevCert);
      ASN_Del(prevprikey);
    }
  } while (ret == SUCCESS);
}

}// end of namespace
