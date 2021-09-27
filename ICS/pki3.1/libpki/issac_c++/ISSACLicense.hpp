// ISSACLicense.hpp: interface for the ca_license class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_LICENSE_HPP_
#define ISSAC_LICENSE_HPP_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <string>

namespace Issac
{

/**
 * license 인증서를 이용한 license 검증을 위한 Sington class
 */
class ISSACLicense
{
public:
  /**
   * Licence 인증서와 비공개키를 load한다.
   *
   * @param licenseName  (In) 제품 license 명
   * @exception runtime_error 인증서, 비공개키 load에 실패하거나 키 쌍 검증에 실패한 경우
   */
  static void loadLicense(std::string certPath, std::string keyPath, 
    std::string licenseName);

  /**
   * ISSACLicense 인증서의 license type에는 "name=value;name=value;"의 형식으로 license_type이 들어가 있다.
   * 이 license type으로부터 해당 권한 명에 대응되는 값을 리턴한다.
   *
   * @return    주어진 권한 명에 대응되는 값(case sensitive)
   * @exception 해당 권한이 들어 있지 않은 경우
   *            license 인증서가 load되어 있지 않은 경우
   *            위의 두 경우에 std::runtime_error이 발생한다.
   */
  static const std::string getPrivilege(std::string privilegeName);
};

} // end of namespace

#endif // ISSAC_LICENSE_HPP_
