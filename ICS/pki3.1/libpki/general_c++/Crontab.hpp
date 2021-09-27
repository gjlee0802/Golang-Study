/**
 * @file     Crontab.hpp
 *
 * @desc     Crontab의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_CRONTAB_HPP_
#define ISSAC_CRONTAB_HPP_

#include <string>
#include <time.h>

namespace Issac
{

class Crontab
{
public:
  static bool isRightTime(time_t *timeCur, std::string expression);
  static bool isValid(std::string expression);
};

}

#endif
