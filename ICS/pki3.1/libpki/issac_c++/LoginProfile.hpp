// LoginProfile.hpp: interface for the LoginProfile class.
//                   by hrcho@pentasecurity.com
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_LOGIN_PROFILE_HPP
#define ISSAC_LOGIN_PROFILE_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <string>
#include <vector>

// from libpki
#include "LogProfile.hpp"

namespace Issac
{

/**
 * PKI의 환경 설정값들을 다루기 위한 sington class
 * 이 class를 상속하는 subclass의 생성자에서 singleton instance를 등록하도록 
 * 해야 한다.
 * pki 부가 모듈(Mailsender, Publisher) 등은 로그인 환경으로 이 클래스를 
 * 써야 한다.
 */
class LoginProfile : public LogProfile
{
public:
  virtual ~LoginProfile();

  static LoginProfile *get();

  // init, login, loginFrom... 관련 함수의 조합으로 로그인 절차를 
  // 간소하게 만든 함수 - 대신 아규먼트가 좀 많다.
  void initAndLogin(int argc, char * const *argv, std::string section,
      std::string logName, const LOG_TABLE_ITEMS items = NULL); 

  virtual void init(int argc, char * const *argv, std::string confFile,
      std::string section, std::string logDir, 
      std::string logName, const LOG_TABLE_ITEMS items = NULL);

  virtual void loginFromPrompt();
  virtual void loginFromPipe();
  virtual void loginFromArgs(int argc, char * const *argv);

  // 주어진 id, passwd로 설정파일에서 비밀정보를 얻고 데이터베이스에 연결한다.
  void login(const std::string &id, const std::string &passwd);

  /**
   * 사용자의 비밀정보를 저장하기 위한 초기화를 수행한다.
   *
   * @param useCurrentKey (in) 새로 추가되는 사용자의 비밀키를 현재 login되어 
   *                           있는 사용자의 비밀키로 할 것인지 여부
   */
  void registerUser(const std::string &id, const std::string &passwd, 
                    bool useCurrentKey = false);

  /**
   * 현재 관리자의 정보를 리턴한다.
   */
  void getIDPASSWD(std::string &id, std::string &passwd) const;

  bool isProfileCipher(const std::string &sec, const std::string &attr) const; 

  // 아래의 두함수는 주어진 sec과 attr로 프로파일에 접근한다.
  // 해당 프로파일이 DB/Cipher 등 인지는 template에서 정의한 바이다.
  virtual void setProfile(const std::string &sec, const std::string &attr, 
                  const std::string &val);
  virtual void setProfile(const std::string &attr, const std::string &val);
  // 아래의 두 함수는 init시에 준 section, 즉 defalult section으로
  // 프로파일에 접근한다. 
  // 해당 프로파일이 DB/Cipher 등 인지는 template에서 정의한 바이다.

  // 만약 template에 정한 바와 관계없이 DB/Cipher 등을 제한하려면
  // 아래의 네 함수를 사용하라.
  Profile *getLP() const { return _lp.get(); } // 로컬 프로파일
  Profile *getELP() const { return _elp.get(); } // 로컬 암호화

  virtual std::string getProfile(const std::string &sec, 
      const std::string &attr) const;
  virtual std::string getProfile(const std::string &attr) const;
  const std::vector<std::string> &getAllSectionAndAttrs() const
  { return _sec_attrs; }
  std::vector<std::string> &getAllModuleNames() { return _mods; }
  const std::vector<std::string> &getAllModuleNames() const { return _mods; }
  std::vector<std::string> &getAllSectionNames() { return _secs; }
  const std::vector<std::string> &getAllSectionNames() const { return _secs; }
  std::vector<std::string> getAllAttrsOfSection(std::string section) const;
  // ^ notice! return value is not reference
  bool isCommandProfile(const std::string &sec, const std::string &attr) const;
  std::string getAllAttrsAndValuesOfSection(std::string section, 
      std::string delimiter1 = " = ", std::string delimiter2 = "\n") const;

  std::string getTmplFile() const { return _tmplFile; }
  std::string getRootDir() const { return _rootDir; }
  std::string getBinDir() const { return _binDir; }
  std::string getSysDir() const { return _sysDir; }
  std::string getConfDir() const { return _confDir; }
  std::string getCrlDir() const { return _crlDir; }
  std::string getExtDir() const { return _extDir; }
  std::string getInstDir() const { return _instDir; }

protected:
  LoginProfile();

  std::string _tmplFile;
  std::string _rootDir;
  std::string _binDir;
  std::string _sysDir;
  std::string _confDir;
  std::string _crlDir;
  std::string _extDir;
  std::string _instDir;

  std::vector<std::string> _sec_attrs; // 모든 섹션과 어트리븃의 연접
  std::vector<std::string> _sec_attrsCipher; // 로컬 암호화된 것들
  //std::vector<std::string> _sec_attrsDB; // DB에 저장되는 것들
  //std::vector<std::string> _sec_attrsDBCipher;
  std::vector<std::string> _mods; // 부가모듈명
  std::vector<std::string> _secs; // 프로파일에서 다루는 모든 섹션
  std::string _id, _passwd;
  std::string _key;  
       // 프로파일을 암호회하기위한 키값, 이것은 _passwd로 암호화되어 저장된다.
  boost::shared_ptr<Profile> _elp;

  void _readProfileTemplate(); 
       // 어떤 어트리븃이 필요하고 또 어떤 어트리븃을 암호화하는지 파악

  /**
   * 암호화되어 저장되어 있는 값들을 access하기 위한 authentication정보들을 
   * 설정한다.
   */
  void _setCurrentUser(const std::string &id, const std::string &passwd);

  static void _create();
};

}

#endif
