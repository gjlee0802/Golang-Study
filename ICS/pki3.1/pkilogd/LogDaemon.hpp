/**
 * @file     LogDaemon.hpp
 *
 * @desc     LogDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_LOG_DAEMON_HPP_
#define ISSAC_LOG_DAEMON_HPP_

#include <string>
#include <vector>

#include "Daemon.hpp"

namespace Issac
{

class LogDaemon : public Daemon
{
private:
  typedef struct
  {
    std::string process;    // CAMGR, CAMSGD와 같은 프로세스 이름
    std::string name;       // SYSTEM으로 고정
    std::string fileName;   // 날짜를 제외한 파일이름
    std::string date;       // 날짜
    std::ios::pos_type pos; // 직전에 처리한 파일 위치
  } LOG_FILE_INFO;

  std::vector<LOG_FILE_INFO> _infos;
  std::string _system;
  std::string _ip;
  int _period;
  int _recovery;


  void _process();           // main process
  void _connectDB();         // LOGDB에 연결 (PKIDB와 연결은 필요없다.)
  void _readConf();          // configure에서 설정 읽기
  void _makeLogFileInfos();  // 다루어야할 로그 파일들의 정보를 생성
  void _insertLOG_CFG();     // 관리도구등을 위해 LOG_CFG 테이블에 정보 입력
  void _restore();           // 지난 시간에 쌓인 로그를 DB에 입력
  std::ios::pos_type _getMaxSizeFromDB(const LOG_FILE_INFO &info);
  // 지난 시간에 쌓인 로그가 어디까지 쌓였는지 DB 질의
  void _processFile(LOG_FILE_INFO &info);
  // 해당 로그 파일에 대해 로그 작업
  std::ios::pos_type _getFileEndPos(const std::string &fileName);
  void _insertLog(const LOG_FILE_INFO &info, const std::string &line, 
       std::ios::pos_type pos);
  // DB에 로그를 한 줄 넣는다

public:
  LogDaemon();
  virtual ~LogDaemon();
  virtual void afterDaemonize();
};

} // namespace Issac

#endif //ISSAC_LOG_DAEMON_HPP_

