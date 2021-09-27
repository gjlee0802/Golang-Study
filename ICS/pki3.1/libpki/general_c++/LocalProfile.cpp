#include <stdexcept>
#include <sstream>

#include "GetProfile.h"
#include "GetProfileEx.hpp"
#include "LocalProfile.hpp"
#include "Profile.hpp"

#ifndef MAX_SEC_LEN
#define MAX_SEC_LEN 300
#endif

#ifndef MAX_PROFILE_KEY_NUM
#define MAX_PROFILE_KEY_NUM 100
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
namespace Issac {

using namespace std;

/** 문자열 값 읽기/쓰기 */
const std::string LocalProfile::get(std::string sec, std::string attr)
{
  string buf;

  GetProfileEx(_filePath, sec, attr, buf);

  return buf;
}

void LocalProfile::set(std::string sec, std::string attr, std::string val)
{
  int ret;
  ret = SetProfile(_filePath.c_str(), sec.c_str(), attr.c_str(), val.c_str());

  if (ret != 0)
  {
    std::ostringstream ost;
    ost << "프로파일 설정 실패 [section:" << sec << ", attribute:" << 
      attr << "]";
    throw runtime_error(ost.str().c_str());
  }
}

std::vector<std::string> LocalProfile::getKeys(std::string sec)
{
	std::vector<std::string> vKeys;
	char* keys[MAX_PROFILE_KEY_NUM];
	
	for( int i = 0; i < MAX_PROFILE_KEY_NUM; i++ ){
		keys[i] = (char*)malloc(MAX_SEC_LEN*sizeof(char));
		memset(keys[i], 0x00, MAX_SEC_LEN);
	}
	
	size_t keyNum = GetKeys(_filePath.c_str(), sec.c_str(), (char**)keys, MAX_PROFILE_KEY_NUM);
	
	for( int i = 0; i < keyNum; i++ ){
			vKeys.push_back(keys[i]);
	}

	for( int i = 0; i < MAX_PROFILE_KEY_NUM; i++ ){
		free(keys[i]);
	}
	return vKeys;
}

} // end of namespace
