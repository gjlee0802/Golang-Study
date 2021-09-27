/**
 * @file     LocalProfile.hpp
 *
 * @desc     LocalProfile의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_LOCAL_PROFILE_HPP_
#define ISSAC_LOCAL_PROFILE_HPP_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Profile.hpp"
#include <vector>
namespace Issac {

class LocalProfile : public Profile
{
protected:
  std::string _filePath;
public:
  LocalProfile(std::string filePath) : _filePath(filePath) {}
  LocalProfile() {}

  virtual ~LocalProfile() {}
  void setPath(std::string filePath) { _filePath = filePath; }

  virtual const std::string get(std::string sec, std::string attr);
  virtual void set(std::string sec, std::string attr, std::string val);
  virtual std::vector<std::string> getKeys(std::string sec);
};

} // end of namespace

#endif

