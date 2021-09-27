// standard headers
#include <iostream>
#include <stdexcept>

#include <boost/shared_ptr.hpp>

// cis headers
#include "asn1.h"
#include "pkimessage.h"
#include "CertHelper.h"
#include "PrivateKeyShare.h"
#include "KeyHistory.h"
#include "CnKStorage.hpp"

// libpki headers
#include "CnK_define.hpp"

using namespace std;
using namespace boost;

using namespace Issac;

int main(int argc, char **argv)
{
  try
  {
    string certFile = "ca.cer";
    string prikeyFile = "ca.shk";

    CertSharedPtr cert;

    // load cert
    cert = CertSharedPtr(CERT_NewFromFile(certFile.c_str()), ASN_Delete);

    if (cert.get() == NULL)
      throw runtime_error("fail to load cert");

    // load prikey
    int ret, reqNum = 0;
    boost::shared_ptr<PrivateKeyInfo> prikeySharedPtr;

    ::KEYSHARE_GetReqInfosNum(&reqNum, prikeyFile.c_str());

    EncryptedPrivateKey *encprikey;
    ASNBuf *bufEncprikey;

    bufEncprikey = ASNBuf_NewFromFile(prikeyFile.c_str());
    if (bufEncprikey == NULL)
      throw runtime_error("fail to load cert");

    encprikey = ASN_New(EncryptedPrivateKey, bufEncprikey);
    ASNBuf_Del(bufEncprikey);
    if (encprikey == NULL)
      throw runtime_error("fail to load key");

    // max 10
    char *ids[10];
    char *passwds[10];
    for (int i = 0; i < reqNum; i++)
    {
      ids[i] = "CA";
      passwds[i] = "CA";
    }
    PrivateKeyInfo *prikeyRaw;
    ret = KEYSHARE_RecoverPrivateKey(&prikeyRaw, encprikey, NULL, 
        const_cast<const char**>(static_cast<char**>(ids)), 
        const_cast<const char**>(static_cast<char**>(passwds)), reqNum);
    ASN_Del(encprikey);

    if (ret != SUCCESS)
      throw runtime_error("fail to decrypt prikey");

    PrivateKeyInfoSharedPtr prikey(prikeyRaw, ASN_Delete);

    cout << "success to load cert and key" << endl;

    //////////////////////////////////////////////////
    // okay! now we just know cert and prikey
    //

    AlgDesc desc = AlgNid_GetHashAlgDesc(NID_SHA1);

    Nid sigAlg; 

    ASNBuf *signedBufRaw = NULL;
    const char *buf = "hello! world";
    BWT len = strlen(buf);
    ret = CKM_Sign(&signedBufRaw, &sigAlg,
        (BYTE *)buf, len, prikey.get(), cert.get(), NULL, desc);
    shared_ptr<ASNBuf> signedBuf(signedBufRaw, free);

    if (ret != SUCCESS)
      throw runtime_error("fail to CKM_Sign");

    cout << "success to sign data" << endl;
    
    ret = CKM_VerifySign(signedBuf.get(),
        (BYTE *)buf, len,
        cert.get(), NULL, sigAlg);

    if (ret != SUCCESS)
      throw runtime_error("fail to CKM_VerifySign");

    cout << "success to verify data" << endl;
  }
  catch (exception &e)
  {
    cout << e.what() << endl;
  }

  return 0;
}

