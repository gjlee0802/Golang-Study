// LogProfile.hpp: interface for the LogProfile class.
//                   by hrcho@pentasecurity.com
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_LOG_PROFILE_HPP
#define ISSAC_LOG_PROFILE_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#ifndef _STRING_INCLUDED_
#include <string>
#define _STRING_INCLUDED_
#endif

#ifndef _IOSTREAM_INCLUDED_
#include <iostream>
#define _IOSTREAM_INCLUDED_
#endif

#include <utility>

#ifndef BOOST_SHARED_PTR_HPP_INCLUDED
#include <boost/shared_ptr.hpp>
#define BOOST_SHARED_PTR_HPP_INCLUDED
#endif

// from libpki
#include "Profile.hpp"
#include "Log.hpp"

#define PKI_LOG_GROUP       "PKI"

namespace Issac
{

/**
 * PKI의 환경 설정값들을 다루기 위한 sington class
 * 이 class를 상속하는 subclass의 생성자에서 singleton instance를 등록하도록 
 * 해야 한다.
 * DB연결이나 암호화 프로파일에 대한 획득, 즉 로그인이 필요없는 모듈은 
 * 이 프로파일을 써야 한다.
 */
class LogProfile
{
public:
  virtual ~LogProfile();

  static LogProfile *get();
  // PKI.ora817ca.192.168.0.33.CAMSGD.10.SYSTEM.20040627 와 같은 로그에서
  // PKI -> logGroup, ora817ca -> logSystemName, CAMSGD -> logName
  // 어차피 해당 어플리케이션은 section이 주어지므로
  // 값을 넣지 않으면 설정 파일의 해당 section에서 LOG_GROUP,
  // LOG_SYSTEM, LOG_HMAC_KEY을 찾는다
  // 만약 해당 섹션에 없으면 SYSTEM섹션에서 GROUP, NAME, HMAC_KEY
  // 를 찾는다.
  // 해당 섹션에서는 LOG_가 붙지만 SYSTEM에서는 붙지 않음에 유의하라.

  void init(int argc, char * const *argv, std::string confFile, 
      std::string section, std::string logDir, std::string logSystemName,
      std::string logName, const LOG_TABLE_ITEMS items = NULL, 
      std::string logGroup = ""); 
  virtual void setProfile(const std::string &sec, const std::string &attr, 
      const std::string &val);
  virtual void setProfile(const std::string &attr, const std::string &val);
  virtual std::string getProfile(const std::string &sec, 
      const std::string &attr) const;
  virtual std::string getProfile(const std::string &attr) const;

  std::string getMyDir() const { return _myDir; }
  std::string getLogDir() const { return _logDir; }
  std::string getLogName() const { return _logName; }
  std::string getLogSystemName() const { return _logSystemName; }
  std::string getLogGroup() const { return _logGroup; }
  std::string getConfFile() const { return _confFile; }
  std::string getMySection() const { return _section; }

  std::string getPidFile(std::string section = "") const;
  static std::string getPidFileName(std::string section);
  void setPidDir(const std::string &relDir2MyDir);

  Log* getLog();

protected:
  LogProfile();

  boost::shared_ptr<Log> _log;
  boost::shared_ptr<Profile> _lp;

  void _initLog(std::string logSystemName, std::string logName, 
      std::string logDir, const LOG_TABLE_ITEMS items, 
      std::string logGroup);

       // log hmac을 위해서 위의 _key를 스티링으로 인코딩한 값 
       // (24byte 이내이어야 한다.)
  std::string _logName; // 로그 이름
  std::string _logSystemName;
  std::string _logGroup;
  std::string _section; // 로그인하는 프로세스의 프로파일 섹션
  std::string _confFile;
  std::string _logDir;
  std::string _myDir;
  std::string _pidDir;

  std::string _logPin;  

  // singleton
  static LogProfile *_inst;
  static void _deadReference();
  static bool _destroyed; // 다른 정적 객체가 이 객체 소멸뒤 언급하는 것을 방비
  static void _create(); // you must make this you opwn version
};

}

#endif

