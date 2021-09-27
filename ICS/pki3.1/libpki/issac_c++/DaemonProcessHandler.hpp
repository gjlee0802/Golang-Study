/**
 * @file     DaemonProcessHandler.hpp
 *
 * @desc     DaemonProcessHandler의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_DAEMON_PROCESS_HANDLER_HPP_
#define ISSAC_DAEMON_PROCESS_HANDLER_HPP_

#include <string>
#include <vector>

namespace Issac
{

// need LogProfile
std::string DaemonProcessStop(std::string section);
std::string DaemonProcessStatus(std::string section);
// don't need LogProfile
std::string DaemonProcessStop(std::string pidFile, std::string moduleName);
std::string DaemonProcessStatus(std::string pidFile, std::string moduleName);

}

#endif
