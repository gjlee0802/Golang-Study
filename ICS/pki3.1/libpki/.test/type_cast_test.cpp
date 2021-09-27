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

#define TEST_HEADER   "\n### �׽�Ʈ �ܰ�: "
#define TEST_HEADER_1 "\n##  "
#define TEST_HEADER_2 "\n#   "

class temp {};

int main(int argc, char * const *argv)
{
  /*
  if (argc != 9)
  {
    cerr << 
        "������ڷ� ������ ������� �Է��ؾ� �մϴ�." << endl
        << "ldapip, port, binddn, passwd" << endl 
        << "�׽�Ʈ�� �۾� �� ��Ʈ���� �߰��� �θ��� DN" << endl 
        << "�׽�Ʈ�� �۾� �� ��Ʈ���� ou �̸�" << endl 
        << "���͸� ������ utf8 ���ڵ� ���� ����" << endl 
        << "�׽�Ʈ �� �� ��Ʈ�� ��������" << endl;

    exit(-1);
  }
  */

  try
  {
    do
    {
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "�⺻ �Լ� ����" << endl;
      ///////////////////////////////////////////////////////////////
      time_t t;
      time(&t);
      ASN *a;
      cout << type2string<time_t>(t) << endl;
      cout << "\n--��� �ܰ��� �׽�Ʈ�� �����Ͽ����ϴ�." << endl;
   }
   while (0);
  }
  catch (std::exception &e)
  {
    cerr << "\n## ������ �߻��Ͽ����ϴ�.(" << e.what() << ")" << endl;
  }

  return 0;
}

