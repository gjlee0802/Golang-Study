// BCipher.cpp: implementation of the BCipher class.
//
//////////////////////////////////////////////////////////////////////

#include <boost/scoped_array.hpp>

#include "sha1.h"
#include "seed.h"
#include "pbkdf.h"
#include "bcipher_op.h"
#include "base64.h"
#include "asn1.h"

#include "BCipher.hpp"

// FIXME
#define SALT "\x12\x34\x56\x78\x90\x34\x12\x78\x12\x34\x56\x78\x90\x34\x12\x78"
const int KEY_LEN = 16;

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
namespace Issac
{

using namespace std;

BCipher::BCipher(std::string pin) : _key(NULL), _iv(NULL)
{
  setPin(pin);
}

BCipher::~BCipher()
{
  if (_key)
    ::BCIPHER_DelKey(_key);
  if (_iv)
    delete[] _iv;
}

void BCipher::setKey(string key)
{
  if (_key)
    ::BCIPHER_DelKey(_key);
  if (_iv)
    delete[] _iv;

  _iv = NULL;
  _key = ::BCIPHER_NewKey(SEED);
  if (_key == NULL)
    throw BCipherException("BCipher::setKey-> error BCIPHER_NewKey");

  ::BCIPHER_MakeKey(_key, 
    reinterpret_cast<unsigned const char *>(key.c_str()), 
    key.size(), SEED);
}

void BCipher::setPin(string pin)
{
  unsigned char buf[128];
  
  // 핀으로 PKCS12 키를 만든다.
  if (::PBKDF_PKCS12(buf, KEY_LEN, PBKDF_PKCS12_ID_ENCKEY, 
    reinterpret_cast<const char *>(pin.c_str()),
    reinterpret_cast<unsigned const char *>(SALT), 
		sizeof(SALT) - 1, 150, SHA1))
  {
    throw BCipherException("BCipher::setPin-> error PBKDF_PKCS12");
  }

  _iv = new unsigned char[16];
  if (::PBKDF_PKCS12(_iv, 16, PBKDF_PKCS12_ID_IV, 
    reinterpret_cast<const char *>(pin.c_str()),
    reinterpret_cast<unsigned const char *>(SALT), sizeof(SALT) - 1, 150, SHA1))
  {
    throw BCipherException("BCipher::setPin-> error PBKDF_PKCS12");
  }

  _key = ::BCIPHER_NewKey(SEED);
  ::BCIPHER_MakeKey(_key, buf, KEY_LEN, SEED);
}

void BCipher::encrypt(std::string &out, const std::string &in)
{
  BCipherContext en;
  ::BCIPHER_Initialize(&en, MODE_CBC, _iv, SEED);

  unsigned int outlen;
  out.resize(in.size() + 16);
  if (::BCIPHER_Encrypt((unsigned char *)(out.c_str()), &outlen, 
    reinterpret_cast<const unsigned char *>(in.c_str()), in.size(), &en, _key, PAD))
  {
    throw BCipherException("BCipher::encrypt-> error BCIPHER_Encrypt");
  }
  out.resize(outlen);
}

void BCipher::decrypt(std::string &out, const std::string &in)
{
  if (in.empty())
  {
    out = "";
    return;
  }
  BCipherContext de;
  ::BCIPHER_Initialize(&de, MODE_CBC, _iv, SEED);

  unsigned int outlen;
  out.resize(in.size() + 16);
  if (::BCIPHER_Decrypt((unsigned char *)(out.c_str()), &outlen, 
    reinterpret_cast<const unsigned char *>(in.c_str()), in.size(), &de, _key, PAD))
  {
    throw BCipherException("BCipher::decrypt-> error BCIPHER_Decrypt");
  }
  out.resize(outlen);
}

void BCipher::encryptAndEncode(std::string &out, const std::string &in)
{
  encrypt(out, in);

  int maxbuf = out.size()*4/3 + 8;
  boost::scoped_array<char> pbuf(new char[maxbuf]);
  ::Base64_Encode(
    pbuf.get(), maxbuf,
    reinterpret_cast<const unsigned char *>(out.c_str()), out.size());

  out = pbuf.get();
}

void BCipher::decodeAndDecrypt(std::string &out, const std::string &in)
{
  if (in.empty())
  {
    out = "";
    return;
  }
  ASNBuf *asnin = ::ASNBuf_New(in.size());
  int ret = ::Base64_Decode(
    reinterpret_cast<unsigned char *>(asnin->data), in.size(),
    reinterpret_cast<unsigned int *>(&asnin->len), in.c_str());
  if (ret != 0)
  {
    ASNBuf_Del(asnin);
    throw BCipherException("Issac::BCipher::decodeAndDecrypt-> in processing Base64_Decode");
  }

  string newin;
  newin.resize(asnin->len);
  memcpy((void *)newin.c_str(), (const void *)asnin->data, asnin->len);

  return decrypt(out, newin);
}

} // end of namespace

