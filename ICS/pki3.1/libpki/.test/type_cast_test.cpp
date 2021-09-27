// by hrcho 
#include <string>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <stdexcept>

#include "asn1.h"

#include "cis_cast.hpp"

using namespace Issac;
using namespace std;

#define TEST_HEADER   "\n### 테스트 단계: "
#define TEST_HEADER_1 "\n##  "
#define TEST_HEADER_2 "\n#   "

class temp {};

int main(int argc, char * const *argv)
{
  /*
  if (argc != 9)
  {
    cerr << 
        "명령인자로 다음을 순서대로 입력해야 합니다." << endl
        << "ldapip, port, binddn, passwd" << endl 
        << "테스트로 작업 할 엔트리가 추가될 부모의 DN" << endl 
        << "테스트로 작업 할 엔트리의 ou 이름" << endl 
        << "디렉터리 서버의 utf8 인코딩 지원 여부" << endl 
        << "테스트 후 이 엔트리 삭제여부" << endl;

    exit(-1);
  }
  */

  try
  {
    do
    {
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "기본 함수 사용법" << endl;
      ///////////////////////////////////////////////////////////////
      time_t t;
      time(&t);
      ASN *a;
      cout << type2string<time_t>(t) << endl;
      cout << "\n--모든 단계의 테스트를 성공하였습니다." << endl;
   }
   while (0);
  }
  catch (std::exception &e)
  {
    cerr << "\n## 오류가 발생하였습니다.(" << e.what() << ")" << endl;
  }

  return 0;
}

