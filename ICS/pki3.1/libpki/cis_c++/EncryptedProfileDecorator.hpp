// EncryptedProfileDecorator.hpp: interface 
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_ENCRYPTED_PROFILE_DECORATOR_HPP_
#define ISSAC_ENCRYPTED_PROFILE_DECORATOR_HPP_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <string>

#include "Profile.hpp"
#include "BCipher.hpp"

namespace Issac {

/**
 * @brief EncryptedProfileDecorator의 interface를 정의한 class
 */
class EncryptedProfileDecorator : public Profile
{
protected:
  Profile *_profile;
  BCipher _cipher;

public:
  EncryptedProfileDecorator(Profile *profile, std::string pin) : 
    _profile(profile), _cipher(pin) {}
  EncryptedProfileDecorator(Profile *profile) : _profile(profile) {}
  virtual ~EncryptedProfileDecorator() { delete _profile; }

  void setPin(std::string pin) { _cipher.setPin(pin); }
  void setKey(std::string key) { _cipher.setKey(key); }

  virtual const std::string get(std::string sec, std::string attr);
  virtual void set(std::string sec, std::string attr, std::string val);
};

} // end of namespace 

#endif

