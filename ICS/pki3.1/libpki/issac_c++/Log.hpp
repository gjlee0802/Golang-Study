/**
 * @file      Log.hpp
 *
 * @desc      Log 관련 함수 및 클래스 선언
 * @author    박지영(jypark@pentasecurity.com)
 * @since     2002.05.22
 */

#ifndef ISSAC_LOG_HPP_
#define ISSAC_LOG_HPP_

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <stdarg.h>

#ifndef _STRING_INCLUDED_H_
#include <string>
#define _STRING_INCLUDED_H_
#endif

#ifndef BOOST_SHARED_PTR_HPP_INCLUDED
#include <boost/shared_ptr.hpp>
#define BOOST_SHARED_PTR_HPP_INCLUDED
#endif

#include <map>
#define PKI_LOG_GROUP       "PKI"
namespace Issac 
{

#define LOG_SEVERITY_NOTICE     0
#define LOG_SEVERITY_FAILURE    1

// 로그코드와 로그 설명을 연결하는 구조체와 클래스
// 외부에서는 쓰이지 않고 Log 및 LogItem class에서 쓰인다. 
#define LOG_TABLE_INVALID_CODE  -1

typedef struct _LOG_TABLE_ITEM
{
  int         code;
  std::string desc;
  int         severity;
  std::string category;
} LOG_TABLE_ITEM, *LOG_TABLE_ITEMS;


/**
 * 로그 기록 API 사용 방법
 *
 * - Log를 기록하기 위해 사용되는 class들은 Log, LogItem, LogTable의
 *  3개의 base class로부터 상속된 class들이다.
 * 
 * - LogTable은 Log 기록에 사용되는 log code와 설명, 범주등을 리스트로 관리하기 위한
 *  class이다.
 *
 * - Log class는 Log 저장소에 쓰는 것을 담당하는 class이며, 해당 저장소에 알맞는
 *  LogItem의 instance를 생성한다.
 * 
 * - LogItem class는 기록할 Log에 대한 정보를 관리하는 class이며, 하나의 log를 기록할 때에는
 *  우선 LogItem의 instance를 생성한 뒤 이를 이용하여 기록해야 한다.
 *
 * - 로그 기록 예)
 *
 *   Log log(....);
 *   char peerName[128];
 *   
 *   LogItemSharedPtr logItem = log.createLogItem();  // LogItem의 instance 생성
 *   logItem->setLogItem(1, "발급된 인증서의 일련번호 : %s", serialnumber);
 *   logItem->setRequester("aa;bb;cc;dd");
 *   logItem->setCertHolder(dn, id);
 *
 *   logItem.write();
 */


/**
 * 로그를 기록하기 위한 class들
 */
class LogItem;
typedef boost::shared_ptr<LogItem> LogItemSharedPtr;

class Log
{
protected :
  class LogImpl; // 구현을 정의한 inner class
  class LogImpl *_impl; 
  void write(LogItem *item);

  /**
   * LogCode들을 다루기 위한 class
   */
  class LogTable : private std::map<int, LOG_TABLE_ITEM>
  {
  public:
    LogTable(const LOG_TABLE_ITEMS items);
    void setItems(const LOG_TABLE_ITEMS items);
    virtual ~LogTable();
  
    LOG_TABLE_ITEM getItem(int code) const;
  };

  LogTable _table;
  
friend class LogItem;

public:
  /**
   * constructor
   *
   * @param logPath       (In) CA/RA가 설치되어 있는 절대 경로.
   *                           Log 파일은 "%pszPath%/log" 밑에 저장된다.
   * @param systemName    (In) Log에 기록될 System 명(ex: RootCA, Class1 CA)
   * @param process       (In) Log에 기록될 Process 명(ex: CAMGR, CAMSGD)
   * @param logName       (In) 이 Log의 명칭(ex : SYSTEM CAMGR, AUDIT CAMSGD)
   * @param passwd        (In) Log의 MAC값 생성에 사용될 password
   */
  Log(const LOG_TABLE_ITEMS items, std::string logPath, 
      std::string systemName, std::string process, std::string passwd,
      std::string group = PKI_LOG_GROUP);
  virtual ~Log();
  virtual LogItemSharedPtr createLogItem();
  LOG_TABLE_ITEM getItem(int code) const { return _table.getItem(code); }
  void setTableItems(const LOG_TABLE_ITEMS items);

  static std::string format(const std::string &format, va_list args);
};

/**
 * 로그를 기록할 item을 다루기 위한 class
 */
class LogItem
{
public:
  virtual ~LogItem() {}
  /**
   * Log를 설정한다.
   * 
   * @param code       (In) 로그 코드
   * @param severity   (In) 로그 종류
   * @param category   (In) 로그 범주
   * @param desc       (In) 로그 설명
   * @param opt        (In) 로그 추가 설명
   */
  void setLogItem(int code, std::string opt, ...);

  /**
   * Log를 기록한다.
   */
  void write() 
  {
    _log.write(this);
  }

  /**
   * 요청자에 대한 정보를 설정한다.
   *
   * @param requester   (In) 요청자에 대한 정보
   */
   void setRequester(std::string peerName, std::string subjectDN, 
       std::string entityID, std::string subjectType);
   void setRequester(std::string requester) { _reqInfo = requester; }
  /**
   * 작업 대상(PKI에서는 인증서 소유자가 됨)에 대한 정보를 설정한다.
   *
   * @param certHolder  (In) 작업 대상에 대한 정보
   */
  void setCertHolder(std::string dn, std::string id);
  void setCertHolder(std::string certHolder) { _holderInfo = certHolder; }
  std::string getDesc() const;

protected:
  int _code;
  std::string _logInfo, _reqInfo, _holderInfo, _desc;

  LogItem(Log &log)
    : _log(log)
  {
    _code = 0;
    _logInfo = ";;;;";
    _reqInfo = ";;;;";
    _holderInfo = ";";
  }
  /**
   * 로그를 기록하기 위한 LogSystem에 대한 reference
   */
  Log &_log;
  /**
   * Log code 값을 리턴한다.
   */
  int getCode() const { return _code; }
  /**
   * Log 설명을 리턴한다.
   */
  std::string getMessage() const;

  friend class Log;
};

}

#endif /* ISSAC_LOG_HPP_ */

