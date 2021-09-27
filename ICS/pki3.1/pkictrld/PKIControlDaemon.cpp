/**
 * @file     PKIControlDaemon.cpp
 *
 * @desc     PKIControlDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <iostream>
#include <sstream>
#include <string>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <algorithm>
#endif

#include <boost/scoped_array.hpp>
#include <boost/tokenizer.hpp>

#include "base_define.h"

// from libpki
#include "Crontab.hpp"
#include "ProcessHandler.hpp"
#include "ProcessCommand.hpp"
#include "Trace.h"
#include "LoginProfile.hpp"
#include "LocalProfile.hpp"
#include "CommandLineArgs.h"
#include "Exception.hpp"
#include "QSLSocket.hpp"

#include "PKIControlDaemon.hpp"
#include "BasicCommand.hpp"
#include "RequestCommandValues.hpp"
#include "ResponseCommandValues.hpp"
#include "ControlDaemonLogTableDefine.hpp"
#include "LoginProcessCommand.hpp"

#ifndef _SLAVE
#include "DBSubject.hpp"
#include "DBPKC.hpp"

#include "dbconn.h"
#include "DBProxy.hpp"

#include "LoginProfileDBConnection.hpp"

#define PERIOD 60
#endif


#define TMPLOG "/tmp/ctrld.log"

namespace Issac
{

using namespace std;
#ifndef _SLAVE
using namespace Issac::DB;
pid_t PKIControlDaemon::_childpid = 0;
#endif

PKIControlDaemon::PKIControlDaemon()
{
}

void PKIControlDaemon::_terminateProcess(int signum)
{
#ifndef _SLAVE
  if (_childpid)
    kill(_childpid, SIGTERM);
#endif
  exit(0);
}

void PKIControlDaemon::_handleException(int signum)
{
  ::abort();
}

void PKIControlDaemon::beforeDaemonize()
{
#ifndef _SLAVE
  if (LoginProfile::get()->getProfile("DB_PROXY") == "yes")
  {
    registerProcess(atoi(LoginProfile::get()->getProfile(
            "PORT_DB").c_str()),
        (MD_PROC)&PKIControlDaemon::_processDBRequest);
  }
#endif
  registerProcess(atoi(LoginProfile::get()->getProfile(
      "PORT_COMMAND").c_str()),
      (MD_PROC)&PKIControlDaemon::_processCommandRequest);
}

void PKIControlDaemon::afterDaemonize()
{
  // signal setting
  ::signal(SIGTERM, _terminateProcess);
  ::signal(SIGINT, _terminateProcess);
  ::signal(SIGTSTP, _terminateProcess);
  ::signal(SIGPIPE, _terminateProcess);
  ::signal(SIGUSR1, _terminateProcess);
  ::signal(SIGUSR2, _terminateProcess);
  ::signal(SIGPOLL, _terminateProcess);
  ::signal(SIGPROF, _terminateProcess);
  ::signal(SIGVTALRM, _terminateProcess);

  ::signal(SIGABRT, _handleException);
  ::signal(SIGQUIT, _handleException);
  ::signal(SIGBUS, _handleException);
  ::signal(SIGSEGV, _handleException);
  ::signal(SIGFPE, _handleException);
  ::signal(SIGILL, _handleException);
  ::signal(SIGSYS, _handleException);
  ::signal(SIGTRAP, _handleException);
  ::signal(SIGXCPU, _handleException);

  // 이곳은 소켓을 만들어 리슨하기 직전에 호출되는 곳이다.
  // 여기에서 다시 포크해서 하나는 루프를 돌며 크론 잡을 처리하고
  // 나머지 하나는 계속 진행해서 디비와 컨트롤 리퀘스트를 처리한다.
#ifndef _SLAVE
  if ((_childpid = fork()) == 0) // child
  {
    while (1)
    {
      sleep(PERIOD);
      _processCron();
    }
    exit(1);
  }
#endif

  // parent-> go ahead
}

void PKIControlDaemon::_sendResult(const std::vector<BasicOutput> &rets,
    Socket &sock)
{
  ResponseCommandValues res;
  res.setBasicOutputs(rets);

  string buf = res.getBuffer();

  sock.sendLengthAndData(buf);
}

#ifndef _SLAVE
DBObjectSharedPtr PKIControlDaemon::_getSenderPKC(const string &dn,
    const string &ser)
{
  // 신청자의 정보 및 인증서 가져오기
  std::ostringstream ost;
  ost << "DN='" << dn << "'";

  DBObjectSharedPtr sender;
  try
  {
    sender = DBEntity::select(ost.str().c_str());
  }
  catch (...)
  {
    TRACE_LOG(TMPLOG, ost.str().c_str());
    throw Exception("해당 요청자가 존재하지 않아 "
        "컨트롤 데몬에서 요청을 허락할 수 없습니다.");
  }

  if (dynamic_cast<DBSubject *>(sender.get())->getType() !=
      PKIDB_ENTITY_TYPE_ADMIN)
  {
    throw Exception("해당 요청자는 관리자가 아니어서 "
        "컨트롤 데몬에서 요청을 허락할 수 없습니다.");
  }

  ost.str("");
  ost << "SER='" << ser << "' AND STAT='" << PKIDB_PKC_STAT_GOOD << "'";
  try
  {
    return DBEntityPKC::select(ost.str());
  }
  catch (...)
  {
    throw Exception("해당 요청자의 유효한 인증서가 존재하지 않아 "
        "컨트롤 데몬에서 요청을 허락할 수 없습니다.");
  }
}
#endif

void PKIControlDaemon::_alarmTerminate(int signum)
{
  LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
      createLogItem());
  logItem->setLogItem(LOG_CONTROL_TIMEOUT_TERMINATE_N, "pid: %d", getpid());
  logItem->write();
}

int PKIControlDaemon::_processCommandRequest()
{
  try
  {
    int timeout =
      atoi(LoginProfile::get()->getProfile("COMMAND_TIMEOUT_HOUR").c_str());
    if (timeout > 0)
    {
      alarm(3600 * timeout);
      signal(SIGALRM, PKIControlDaemon::_alarmTerminate);
    }
    string buf;
    string dn, ser;
#ifndef _SLAVE
    QSLSocket sock = static_cast<QSLSocket>(getSockConn());
    try
    {
      sock.recvRequester(dn, ser);
    }
    catch (...)
    {
      exit(-1);
      // L4가 체크해서 로그 남기면 너무 번거롭다.
      return -1;
    }
    DBObjectSharedPtr senderCert;
    try
    {
      DB::LoginProfileDBConnection_Connect();
      senderCert = _getSenderPKC(dn, ser);
    }
    catch (exception &e)
    {
      DB::DBConnection::close();
      LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
          createLogItem());
      logItem->setLogItem(LOG_CONTROL_DAEMON_NO_SUCH_SENDER_ERROR_N,
          e.what());
      logItem->write();
      sock.reply(e.what(), false);
      return -1;
    }
    sock.reply("session request accepted");
    sock.initServerSession(dynamic_cast<DBPKC *>
        (senderCert.get())-> getCertificate().get());
    // DB Connection Close
    DB::DBConnection::close();
#else
    Socket sock = getSockConn();
#endif

    while (1)
    {
      try
      {
        sock.recvLengthAndData(buf);
      }
      catch (...)
      {
        return -1;
      }

      RequestCommandValues v;
      v.loadFromBuffer(buf);
      BasicInput input;
      v.getInput(input.first, input.second);
      vector<BasicOutput> rets;

      ExternalCommandMap::const_iterator i =
        _extCmds.find(v.getRequestID());

      if (i != _extCmds.end())
      {
        LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
            createLogItem());
        string req = sock.getPeerName();
        req += ";";
        req += dn + ";;;";
        logItem->setRequester(req);
        logItem->setLogItem(LOG_CONTROL_DAEMON_PROCESS_COMMAND_N,
            "'%s'", v.getRequestID().c_str());
        logItem->write();

        TRACE_LOG(TMPLOG, "execute method: %s, %s, %s",
            v.getRequestID().c_str(), input.first.c_str(),
            input.second.c_str());
        rets = i->second->execute(input);
        _sendResult(rets, sock);
      }
      else if (!v.getRequestID().empty())
      {
        LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
            createLogItem());
        logItem->setLogItem(LOG_CONTROL_DAEMON_NO_SUCH_COMMAND_N,
            "잘못된 명령 요청 : '%s'", v.getRequestID().c_str());
        logItem->write();

        rets.push_back(make_pair(-1, v.getRequestID() + ": no such command"));
        _sendResult(rets, sock);
      }
    }
  }
  catch (exception &e)
  {
#ifndef _SLAVE
    DB::DBConnection::close();
#endif
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
        createLogItem());
    logItem->setLogItem(LOG_CONTROL_DAEMON_RUNTIME_ERROR_N,
        string("while processing command request : ") + e.what());
    logItem->write();
  }

  exit (0);
}

#ifndef _SLAVE
static const ProxyResultSet MakeLabeledValues(dbconn *conn)
{
  ProxyResultSet vals;
  vals.reserve(conn->fieldCount);

  for (int i = 0; i < conn->fieldCount; ++i)
  {
    BASE_DBField *field = conn->getFieldByColumn(i);
    TRACE_LOG(TMPLOG, "%d : %p", i, field);
    assert(field);

    if (field->fieldType == BASE_DBField::FT_TIMESTAMP ||
      field->fieldType == BASE_DBField::FT_DATE ||
      field->fieldType == BASE_DBField::FT_TIME ||
      field->fieldType == BASE_DBField::FT_DATETIME)
    {
      char buf[256];
      ::sprintf(buf, "%ld", field->asDateTime());
      vals.push_back(buf);
    }
    else if (field->fieldType == BASE_DBField::FT_INTEGER ||
      field->fieldType == BASE_DBField::FT_SMALLINT ||
      field->fieldType == BASE_DBField::FT_WORD ||
      field->fieldType == BASE_DBField::FT_FLOAT)
    {
      char buf[256];
      ::sprintf(buf, "%ld", field->asInteger());
      vals.push_back(buf);
    }
    else vals.push_back(field->asString());
  }

  return vals;
}

static void ParseDBInfo(string info, string &name, string &ip, string &id,
    string &passwd)
{
  string::size_type pos1, pos2;
  pos1 = 0;

  pos2 = info.find("\n", pos1);
  if (pos1 == string::npos)
    throw Exception("bad db proxy connection info");
  name = info.substr(pos1, pos2 - pos1); pos1 = pos2 + 1;

  pos2 = info.find("\n", pos1);
  if (pos1 == string::npos)
    throw Exception("bad db proxy connection info");
  ip = info.substr(pos1, pos2 - pos1); pos1 = pos2 + 1;

  pos2 = info.find("\n", pos1);
  if (pos1 == string::npos)
    throw Exception("bad db proxy connection info");
  id = info.substr(pos1, pos2 - pos1); pos1 = pos2 + 1;

  pos2 = info.find("\n", pos1);
  if (pos1 == string::npos)
    throw Exception("bad db proxy connection info");
  passwd = info.substr(pos1, pos2 - pos1); pos1 = pos2 + 1;
}

static void RedirectProxyDBConn(const string info)
{
  string name, ip, id, passwd;
  ParseDBInfo(info, name, ip, id, passwd);
  TRACE_LOG(TMPLOG, "%s, %s, %s, %s, %s", name.c_str(),
      ip.c_str(), id.c_str(), passwd.c_str(), PRETTY_TRACE_STRING);

  if (LoginProfile::get()->getProfile("PKIDB", "IP") != ip
    || LoginProfile::get()->getProfile("PKIDB", "ID") != id
    || LoginProfile::get()->getProfile("PKIDB", "PASSWORD") != passwd
    || LoginProfile::get()->getProfile("PKIDB", "PASSWORD") != name)
  {
    DBConnection::close();
    DBConnection::connect(ip, id, passwd, name);
  }
}

int PKIControlDaemon::_processDBRequest()
{
  try
  {
    int timeout =
      atoi(LoginProfile::get()->getProfile("DB_PROXY_TIMEOUT_HOUR").c_str());
    if (timeout > 0)
    {
      alarm(3600 * timeout);
      signal(SIGALRM, PKIControlDaemon::_alarmTerminate);
    }
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    QSLSocket sock = static_cast<QSLSocket>(getSockConn());
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

    // receive dbInfo, dn, ser
    string dbInfo, dn, ser;
    try
    {
      sock.Socket::recvLengthAndData(dbInfo);
    }
    catch (...)
    {
      exit(-1);
      // L4가 체크해서 로그 남기면 너무 번거롭다.
      return -1;
    }
    DB::LoginProfileDBConnection_Connect();
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    sock.recvRequester(dn, ser);
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    DBObjectSharedPtr senderCert;
    try
    {
      senderCert = _getSenderPKC(dn, ser);
      RedirectProxyDBConn(dbInfo);
    }
    catch (const exception& e)
    {
      LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
          createLogItem());
      logItem->setLogItem(LOG_CONTROL_DAEMON_NO_SUCH_SENDER_ERROR_N,
          e.what());
      logItem->write();
      TRACE_LOG(TMPLOG, e.what());
      sock.reply(e.what(), false);
      return -1;
    }
    sock.reply("ok");
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    sock.initServerSession(
      dynamic_cast<DBPKC *>(senderCert.get())->getCertificate().get());
    TRACE_LOG(TMPLOG,"6");

    while (true)
    {
      // 메시지 수신
      std::string recvBuf;
      sock.recvLengthAndData(recvBuf);
      TRACE_LOG(TMPLOG,"7");

      // 명령 수행
      dbconn *dbConn = static_cast<dbconn *>(DBConnection::getConn());
      TRACE_LOG(TMPLOG,"7-1");
      TRACE_LOG(TMPLOG, "%p", dbConn);

      bool ret = false;
      ProxyResultSet vals;
      BT16 opCode = ntohs(*reinterpret_cast<const BT16 *>(recvBuf.c_str()));
      switch (opCode)
      {
      case ProxyResultSet::DISCONNECT :
        ret = dbConn->disconnect();
        break;

      case ProxyResultSet::EXECUTE :
        TRACE_LOG(TMPLOG, recvBuf.c_str() + sizeof(BT16));
        ret = dbConn->execute(recvBuf.c_str() + sizeof(BT16));
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        if (ret && !dbConn->eof)
        {
          TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
          vals = MakeLabeledValues(dbConn);
          int i;
          for (i = 0; i < dbConn->fieldCount; ++i){
            vals.insert(
              vals.begin(), dbConn->getFieldByColumn(i)->fieldName);
            TRACE_LOG(TMPLOG, dbConn->getFieldByColumn(i)->fieldName.c_str());
          }
        }
        break;

      case ProxyResultSet::NEXT :
      {
        const int ROW_NUM_FOR_EACH_NEXT = 10;
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

        int i;
        for (i = 0; i < ROW_NUM_FOR_EACH_NEXT; ++i)
        {
          TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
          ret = dbConn->next();
          if (!ret || dbConn->eof)
          {
            TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
            //vals.push_back(ProxyResultSet::ROW_SEPARATOR);
            ret = true;
            break;
          }
          else
          {
            TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
            ProxyResultSet tempVals(MakeLabeledValues(dbConn));
            vals.insert(vals.end(), tempVals.begin(), tempVals.end());
          }
        }
        break;
      }
      case ProxyResultSet::RESULT_CLOSE :
        ret = dbConn->resultClose();
        break;
      case ProxyResultSet::TRANS_BEGIN :
        ret = dbConn->transBegin();
        break;
      case ProxyResultSet::TRANS_COMMIT :
        ret = dbConn->transCommit();
        break;
      case ProxyResultSet::TRANS_ROLLBACK :
        ret = dbConn->transRollback();
        break;
      } // end of switch

      // 응답 메시지 만들기
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      boost::scoped_array<char> sendBuf;
      int len;
      if (ret == false)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        len = sizeof(BT16) + dbConn->errorMsg().size() + 1;
        sendBuf.reset(new char[len]);
        *reinterpret_cast<BT16 *>(sendBuf.get()) =
          htons(ProxyResultSet::FAILURE);
        ::memcpy(
          sendBuf.get() + sizeof(BT16), dbConn->errorMsg().c_str(),
          len - sizeof(BT16));
      }
      else
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        BT16 retOpCode = ProxyResultSet::SUCCESSFUL;
        if (opCode == ProxyResultSet::EXECUTE)
        {
           const std::string str(vals.getBuf());
           len = sizeof(BT16) + str.size() + 1;
           sendBuf.reset(new char[len]);
           ::memcpy(sendBuf.get() + sizeof(short), str.c_str(),
               str.size() + 1);
		   if (dbConn->recordNum == 0 || dbConn->eof)
             retOpCode = ProxyResultSet::NO_MORE_DATA;
    	}
    	else if( opCode == ProxyResultSet::NEXT)
        {
          if (opCode == ProxyResultSet::EXECUTE)
          {
            // unisql이나 pgsql만 recordCount가 가능하고
            // 이 경우 recordCount로서 no more data 여부를 판단.
            if (dbConn->__driver == dbconn::UNISQL ||
              dbConn->__driver == dbconn::PGSQL)
            {
              if (dbConn->recordCount == 0 || dbConn->eof)
                retOpCode = ProxyResultSet::NO_MORE_DATA;
            }
            // 이외의 db는 recordCount가 불가능하므로
            // recordNum으로서 no more data 여부를 판단.
            else
            {
              if (dbConn->recordNum == 0 || dbConn->eof)
                retOpCode = ProxyResultSet::NO_MORE_DATA;
            }
          }

          if (retOpCode == ProxyResultSet::SUCCESSFUL)
          {
            const std::string str(vals.getBuf());
            len = sizeof(BT16) + str.size() + 1;
            sendBuf.reset(new char[len]);
            ::memcpy(sendBuf.get() + sizeof(short), str.c_str(),
                str.size() + 1);
          }
          else
          {
            len = sizeof(BT16);
            sendBuf.reset(new char[len]);
          }
        }
        else
        {
          len = sizeof(BT16);
          sendBuf.reset(new char[len]);
        }
        // opcode 쓰기
        *reinterpret_cast<BT16 *>(sendBuf.get()) = htons(retOpCode);
      } // end of if (ret == false)

      // 응답 메시지 전송
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      sock.sendLengthAndData(sendBuf.get(), len);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    } // end of while
  }
  catch (const exception& e)
  {
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
        createLogItem());
    logItem->setLogItem(LOG_CONTROL_DAEMON_RUNTIME_ERROR_N,
        string("while processing DB proxing: ") + e.what());
    logItem->write();
    TRACE_LOG(TMPLOG, "1 : %s", e.what());
  }

  exit(0);
}

void PKIControlDaemon::_processCron()
{
  time_t t;
  time(&t);

  try
  {
    // 주기적 커맨드 실행
    static LocalProfile l(LoginProfile::get()->getTmplFile());
    string secs = l.get("CRONTAB", "SECTION");
    boost::tokenizer< boost::escaped_list_separator<char> > tok(secs);

    for (boost::tokenizer< boost::escaped_list_separator<char> >::iterator i =
        tok.begin(); i != tok.end(); ++i)
    {
      if (i->empty())
        continue;

      string exp = LoginProfile::get()->getProfile(string("CRONTAB_") + *i,
          "PERIOD");
      string name = LoginProfile::get()->getProfile(string("CRONTAB_") + *i,
          "NAME");
      string args = LoginProfile::get()->getProfile(string("CRONTAB_") + *i,
          "ARGS");
      if (!exp.empty() && !name.empty() && !args.empty()
          && Crontab::isValid(exp) && Crontab::isRightTime(&t, exp))
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        if ((fork()) == 0) // child
        {
          TRACE_LOG(TMPLOG, "%s\n%s", name.c_str(), PRETTY_TRACE_STRING);
          LoginProcessCommand cmd(name);
          cmd.execute(make_pair(args, string("")));
          exit(0);
        }
      }
    }
  }
  catch (const exception& e)
  {
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
        createLogItem());
    logItem->setLogItem(LOG_CONTROL_DAEMON_RUNTIME_ERROR_N,
        string("while processing Crontab : ") + e.what());
    logItem->write();
    TRACE_LOG(TMPLOG, "1 : %s", e.what());
  }
}
#endif

}
