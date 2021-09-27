/**
 * @file     ProcessHandler.hpp
 *
 * @desc     ProcessHandler의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_PROCESS_HANDLER_HPP_
#define ISSAC_PROCESS_HANDLER_HPP_

#include <unistd.h>
#include <string>
#include <vector>

#include <boost/shared_array.hpp>

namespace Issac
{

int ProcessExecute(std::string path, std::string arg, std::string input, 
    std::string &output);

// 만약 스크립트를 실행할 이유가 있으면 - 가령 bash - 이 함수로 패쓰를 설정
void SetProcessExecuteShell(std::string shellPath);

// string의 연접으로 전달된 실행인자를 char **로 바꾼다.
void MakeExecuteArgs(std::string path, std::string arg, 
    std::vector<std::string> &args);
boost::shared_array<char *> MakeCharPtrs(const std::vector<std::string> &args);

}

#endif

