/**
 * @file     LogDaemon.hpp
 *
 * @desc     LogDaemon�� �⺻ ����� �����ϴ� Ŭ����
 * @author   ������(hrcho@pentasecurity.com)
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
    std::string process;    // CAMGR, CAMSGD�� ���� ���μ��� �̸�
    std::string name;       // SYSTEM���� ����
    std::string fileName;   // ��¥�� ������ �����̸�
    std::string date;       // ��¥
    std::ios::pos_type pos; // ������ ó���� ���� ��ġ
  } LOG_FILE_INFO;

  std::vector<LOG_FILE_INFO> _infos;
  std::string _system;
  std::string _ip;
  int _period;
  int _recovery;


  void _process();           // main process
  void _connectDB();         // LOGDB�� ���� (PKIDB�� ������ �ʿ����.)
  void _readConf();          // configure���� ���� �б�
  void _makeLogFileInfos();  // �ٷ����� �α� ���ϵ��� ������ ����
  void _insertLOG_CFG();     // ������������ ���� LOG_CFG ���̺� ���� �Է�
  void _restore();           // ���� �ð��� ���� �α׸� DB�� �Է�
  std::ios::pos_type _getMaxSizeFromDB(const LOG_FILE_INFO &info);
  // ���� �ð��� ���� �αװ� ������ �׿����� DB ����
  void _processFile(LOG_FILE_INFO &info);
  // �ش� �α� ���Ͽ� ���� �α� �۾�
  std::ios::pos_type _getFileEndPos(const std::string &fileName);
  void _insertLog(const LOG_FILE_INFO &info, const std::string &line, 
       std::ios::pos_type pos);
  // DB�� �α׸� �� �� �ִ´�

public:
  LogDaemon();
  virtual ~LogDaemon();
  virtual void afterDaemonize();
};

} // namespace Issac

#endif //ISSAC_LOG_DAEMON_HPP_

