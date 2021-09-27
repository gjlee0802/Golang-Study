// AuthorityLoginProfile.hpp: interface for the AuthorityLoginProfile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_AUTHORITY_LOGIN_PROFILE_HPP
#define ISSAC_AUTHORITY_LOGIN_PROFILE_HPP

// from libpki
#include "Profile.hpp"
#include "CnKStorage.hpp"
#include "Log.hpp"
#include "LoginProfile.hpp"

namespace Issac
{

class AuthorityLoginProfile : public LoginProfile
{
public:
  virtual ~AuthorityLoginProfile();
  static AuthorityLoginProfile *get();

  virtual void init(int argc, char * const *argv, std::string confFile,
      std::string section, std::string logDir,
      std::string logName, const LOG_TABLE_ITEMS items = NULL);

  virtual void loginFromPrompt();
  virtual void loginFromPipe();
  virtual void loginFromArgs(int argc, char * const *argv);

  void login(
    const std::vector< std::pair<std::string, std::string> > &id_passwds);

  /**
   * Host의 인증서와 비공개키 중 주어진 SubjectKeyIdentifier를 갖는 인증서 반환
   */
  CnKSharedPtr getMyCnK(SubjectKeyIdentifier *keyid = NULL);
  /**
   * Domain의 기본 대칭키 알고리즘을 리턴한다.
   */
  Nid getDefaultSymmAlgNid();


  std::vector< std::pair<std::string, std::string> > &getIDPASSWDs()
  { return _id_passwds; }

  virtual std::string getMyName() const;

  /**
   * Host의 인증서와 비공개키(들)을 리턴한다.
   */
  CnKSharedPtrs getMyCnKs();

  /**
   * CA면 자신의 인증서를 RA/AA면 CA의 인증서를 리턴한다.
   */
  virtual CertSharedPtrs getCACerts();

  int getReqAdminNum() const { return _reqAdminNum; }
  std::string getAuthCertFile() const { return _authCertFile; }
  std::string getAuthPrikeyFile() const { return _authPrikeyFile; }
  std::string getLicenseCertFile() const { return _licenseCertFile; }
  std::string getLicensePrikeyFile() const { return _licensePrikeyFile; }
  std::string getKeyHistFile() const { return _keyHistFile; }
  std::string getInstCheckFile() const { return _instCheckFile; }

  Profile *getDP() const { return _dp.get(); } // 로컬 암호화

protected:
  AuthorityLoginProfile();

  static void _create();

  boost::shared_ptr<Profile> _dp;

  CnKSharedPtrs _myCnKs;
  CertSharedPtrs _caCerts;
  Nid _nidSymmAlg;
  std::vector< std::pair<std::string, std::string> > _id_passwds;
  int _reqAdminNum;

  void _setDBSelf();
  void _checkDBSchema();
  virtual void _setDBCA();

  std::string _authPrikeyFile;
  std::string _licenseCertFile;
  std::string _licensePrikeyFile;
  std::string _authCertFile;
  std::string _keyHistFile;
  std::string _instCheckFile;
};

}

#endif

