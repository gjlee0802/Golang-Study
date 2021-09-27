// ISSACISSACLicense.cpp: implementation of the ca_license class.
//
//////////////////////////////////////////////////////////////////////

// standard headers
#include <string>
#include <map>
#include <stdexcept>

#include "license.h"

// libpki headers
#include "CertHelper.h"
#include "ISSACLicense.hpp"

namespace Issac
{

static std::map<std::string, std::string> str_pair_map;

static void ParseISSACLicenseType(std::string licenseType)
{
#ifdef WITHOUT_LICENSE
  return;
#endif
  str_pair_map.clear();
  
  char *pos, *subpos;
  char buf[1024], name[64], val[64];

  ::strcpy(buf, licenseType.c_str());

  pos = ::strtok(buf, ";");
  while (pos != NULL)
  {
    if ((subpos = ::strchr(pos, '=')) == NULL)
      str_pair_map[pos] = "";
    else
    {
      ::strncpy(name, pos, (subpos-pos));
      name[subpos-pos] = '\0';
      ::strcpy(val, subpos + 1);
      str_pair_map[name] = val;
    }
    pos = ::strtok(NULL, ";");
  }
}

/**
 * Licence 인증서와 비공개키를 load한다.
 *
 * @exception std::_error 인증서, 비공개키 load에 실패하거나 키 쌍 검증에 실패한 경우
 */
void ISSACLicense::loadLicense(std::string certPath, std::string keyPath, std::string licenseName)
{
#ifdef WITHOUT_LICENSE
  return;
#endif
  int ret;
  char buf[1024];

  // 인증서내의 license값 검사
  ret = ::LICENSE_CheckCertificate(
    buf, const_cast<char*>(certPath.c_str()), 
    const_cast<char*>(licenseName.c_str()));

  if (ret != 0)
  {
    switch (ret)
    {
    case ER_LICENSE_INVALID_VERIFYSTRING:
      throw std::runtime_error((std::string("ISSACLicense is not for ") + 
        licenseName).c_str());
      break;
    case ER_LICENSE_INVALID_HOST:
      throw std::runtime_error("ISSACLicense is not permitted for this host. Please check IP address");
      break;
    case ER_LICENSE_INVALID_VALIDITYPERIOD:
      throw std::runtime_error("ISSACLicense is not valid yet or expired");
      break;
    default:
      throw std::runtime_error("Fail to load license certificate");
    }
  }

  // 키 쌍 검사
  ret = ::LICENSE_CheckKeyPair(
    const_cast<char*>(keyPath.c_str()), const_cast<char*>(certPath.c_str()));
  if (ret != 0)
  {
    switch (ret)
    {
    case ER_LICENSE_CANNOT_LOAD_PRIKEY:
    case ER_LICENSE_CANNOT_DECODE_PRIKEY:
      throw std::runtime_error("Fail to read license private key");
      break;
    case ER_LICENSE_INVALID_KEYPAIR:
      throw std::runtime_error("Fail to check license certificate and private key pair");
      break;
    default:
      throw std::runtime_error("ISSACLicense error");
    }
  }

  ParseISSACLicenseType(buf);
}

/**
 * ISSACLicense 인증서의 license type에는 "name=value;name=value;"의 형식으로 license_type이 들어가 있다.
 * 이 license type으로부터 해당 권한 명에 대응되는 값을 리턴한다.
 *
 * @return    주어진 권한 명에 대응되는 값
 * @exception ISSACLicensePrivilegeException 해당 권한이 들어 있지 않은 경우
 *            ISSACLicenseException          license 인증서가 load되어 있지 않은 경우
 */
const std::string ISSACLicense::getPrivilege(std::string privilegeName) 
{
  std::map<std::string, std::string>::iterator val;

  val = str_pair_map.find(privilegeName);

  if (val != str_pair_map.end()) return str_pair_map[privilegeName];

  throw std::runtime_error((std::string("Can't find privilege: ") + privilegeName).c_str());
}

} // end of namespace
