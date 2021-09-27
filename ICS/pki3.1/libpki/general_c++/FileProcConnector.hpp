/**
 * @file     FileProcConnector.hpp
 *
 * @desc     FileProcConnector의 기본 기능을 정의하는 클래스
 *           로그 처럼 날짜이름으로 쌓이는 파일을 프로세싱하는 
 *           모듈이 갖추어야 할 resume 기능을 중심으로 구현된 클래스
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2004.4.24
 *
 */
#ifndef ISSAC_FILE_PROC_CONNECTOR
#define ISSAC_FILE_PROC_CONNECTOR

#include <string>
#include <vector>
#include <unistd.h>

namespace Issac
{

class FileProcConnector
{
protected:
  std::string _dataDir;
  std::string _format;
  std::string _prefix;
  std::string _suffix;

  std::string _histDir;
  std::string _key;

  std::string _getNextDayFilePath(std::string filePath);
  std::string _getTodayFilePath();
public:
  FileProcConnector();
  virtual ~FileProcConnector();
  
  inline std::string getHistoryFile();

  void setDataFileInfo(std::string dir, std::string format, 
      std::string prefix, std::string suffix);
  void setHistoryFileInfo(std::string dir, std::string key); 

  bool getNextLine(std::string &line, std::string &filePath, 
      std::ios::pos_type &pos);

  void getLastAppliedFilePathAndPos(
      std::string &filePath, std::ios::pos_type &pos);
  void setLastAppliedFilePathAndPos(const std::string &filePath, 
      const std::ios::pos_type &pos);
};

}

#endif

