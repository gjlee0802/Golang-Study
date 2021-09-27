// pki_encrypted_profile.h: interface for the pki_encrypted_profile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_BCIPHER_HPP
#define ISSAC_BCIPHER_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string>

#include "Exception.hpp"

typedef struct _BCipherKey BCipherKey;

namespace Issac
{

class BCipherException : public Exception
{
public:
  BCipherException(const std::string &s = 
    "Issac::BCipherException") : Exception(s) {}
};

/**
 * 간단한 블럭 암호화를 위한 클래스 - std::string은 size를 조절해서 binary도 담을 수 있다.
 */
class BCipher
{
public:
  BCipher() { _key = NULL; _iv = NULL; }
  BCipher(std::string pin); // 핀으로부터 초기화
  void setPin(std::string key);
  void setKey(std::string key); // 키로부터 초기화
  virtual ~BCipher();
  // 오류시 runtime_error를 throw 한다.
  void encrypt(std::string &out, const std::string &in);
  void decrypt(std::string &out, const std::string &in);
  void encryptAndEncode(std::string &out, const std::string &in);
  void decodeAndDecrypt(std::string &out, const std::string &in);

protected:
  BCipherKey    *_key;
  unsigned char *_iv;
};

} // end of namespace

#endif // ISSAC_BCIPHER_HPP


