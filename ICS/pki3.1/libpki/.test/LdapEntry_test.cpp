// by hrcho
// ./test 192.168.0.33 1092 cn=Manager 12345678 "ou=iSign,o=pentasecurity, c=kr" __test_ou pkiCA auth.cer 1 1

#include <stdio.h>
#include <unistd.h>

#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>

#include "LdapEntry.hpp"

using namespace Issac;
using namespace std;

#define TEST_HEADER   "\n### 테스트 단계: "
#define TEST_HEADER_1 "\n##  "
#define TEST_HEADER_2 "\n#   "

#define ___

int main(int argc, char * const *argv)
{
#define ___
#ifdef ___
  try
  {
    sleep(3);

    for (int i = 0; i < 10; ++i)
    {
      char *attrs[3] = { "cn", NULL };
      LdapEntry::setEncodeMode(1);
      LdapEntry t;
      t.ldapFromServer(
          "cn=CA131000001,ou=gpki, o=Government of Korea, c=kr", 0,
          LDAP_BIND_INFO("ldap.gcc.go.kr"), NULL);
      cout << t.getDesc() << endl;
      sleep(2);
    }
    sleep(5);
  }
  catch (exception &e)
  {
    cerr << e.what();
  }
  exit(0);
}
#else
  if (argc != 11)
  {
    cerr << 
        "명령인자로 다음을 순서대로 입력해야 합니다." << endl
        << "ldapip, port, binddn, passwd" << endl 
        << "테스트로 작업 할 엔트리가 추가될 부모의 DN" << endl 
        << "테스트로 작업 할 엔트리의 ou 이름" << endl 
        << "테스트로 작업 할 CA 엔트리의 objectclass 이름" << endl 
        << "테스트로 작업 할 CA 인증서의 파일 경로" << endl 
        << "디렉터리 서버의 utf8 인코딩 지원 여부" << endl 
        << "테스트 후 이 엔트리 삭제여부" << endl;

    exit(-1);
  }

  bool added = false;
  LDAP_BIND_INFO info(argv[1], atoi(argv[2]), argv[3], argv[4]);
  LDAP_BIND_INFO infoAnony(argv[1], atoi(argv[2]));
  const char *baseDn = argv[5];
  const string testDn = string("ou=") + argv[6] + ", " + baseDn;
  const string caObjectclass = argv[7];
  const string caCertPath = argv[8];
  LdapEntry::setEncodeMode(atoi(argv[9]));
  bool del = atoi(argv[10]);

  try
  {
    do
    {
      LdapEntry e;
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "기본 함수 사용법" << endl;
      cout << "-AttributeCompare 함수:" << endl;
      cout << " tes, TES 비교결과: " << AttributeCompare("tes", "TES") << endl;
      cout << " tes;binary, TES 비교결과: " 
           << AttributeCompare("tes;binary", "TES") << endl;
      cout << " test, TES 비교결과: " 
           << AttributeCompare("test", "TES") << endl;
      cout << " aaa, test;binary 비교결과: " 
           << AttributeCompare("aaa", "test;binary") << endl;
      cout << "-DnCompare 함수:" << endl;
      cout << " 'cn=manager,c=kr', 'cn=Manager, c=kr' 비교결과: " 
           << DnCompare("cn=manager,c=kr", "cn=Manager, c=kr") << endl;
      cout << " 'cn=mana,c=kr', 'cn=Manager, c=kr' 비교결과: " 
           << DnCompare("cn=mana,c=kr", "cn=Manager, c=kr") << endl;
      cout << " 'cn=manager,c=kr', 'cn=Mana, c=kr' 비교결과: " 
           << DnCompare("cn=manager,c=kr", "cn=Mana, c=kr") << endl;
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "부모 DN 읽기 테스트" << endl;
      e.ldapFromServer(baseDn, 0, infoAnony);
      cout << e.getDesc();
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "잘못된 DN 읽기 (기대 오류: no such object)" 
           << endl;
      try
      {
        e.ldapFromServer("cn=__bad__dn", 0, infoAnony);
      }
      catch (std::exception &e)
      {
        cout << "정상적으로 오류발생: " << e.what() << endl;
      }
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "엔트리 추가" << endl;
      cout << TEST_HEADER_1 << "테스트 루트 추가" << endl;
      added = true;
      e.clear();
      e.setDn(testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", LdapEntry::getRdnValue(e.getDn()).c_str(),
          ""));
      e.push_back(LdapAttribute("seeAlso", "see what?", ""));
      e.push_back(LdapAttribute("description", "테스트", ""));
      e.push_back(LdapAttribute("l", "washington, d.c.", ""));
      e.ldapAdd(0, info);
      cout << "추가된 엔트리: " << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;
      added = true;

      cout << TEST_HEADER_1 << "테스트 루트 및에 엔트리 1 추가" << endl;
      e.clear();
      e.setDn(string("ou=test_child1, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child1", ""));
      e.ldapAdd(0, info);
      cout << "추가된 엔트리: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;

      cout << TEST_HEADER_1 << "테스트 루트 및에 엔트리 2 추가" << endl;
      e.clear();
      e.setDn(string("ou=test_child2, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child2", ""));
      e.ldapAdd(0, info);
      cout << "추가된 엔트리: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;
 
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "엔트리 하위노드까지 검색" << endl;
      vector<LdapEntry> entries;
      entries.clear();
      LdapEntry::ldapSearchSync(entries, testDn, LDAP_SCOPE_SUBTREE, 
          "objectclass=*", NULL, 0, NULL, info); 
      cout << entries.size() << " 개 검색" << endl;
      for_each(entries.begin(), entries.end(), mem_fun_ref(&LdapEntry::print));
 
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "엔트리 변경" << endl;
      cout << TEST_HEADER_1 << "두 개체의 비교를 통한 변경" << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      LdapEntry eMod = e;
      cout << "변경전: " << endl;
      cout << eMod.getDesc() << endl;

      cout << "변경 내역: description에 'test'와 'test2' 추가, "
              "seealso를 '안볼께'로 변경, l을 삭제, st에 rodeo를 넣어서 추가"
           << endl;
      eMod.getAttribute("description")->push_back("test");
      eMod.getAttribute("description")->push_back("test2");
      (*(eMod.getAttribute("seealso")))[0] = "안볼께";
      eMod.erase(eMod.getAttribute("l"));
      eMod.push_back(LdapAttribute("st", "rodeo", ""));

      cout << "ldapModifyAttribute 실행" << endl;
      LdapEntry eNew = e.compareEntry(eMod);
      eNew.ldapModifyAttribute(0, info);

      cout << "변경 후 LDAP에서 가져온 엔트리: " << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;
  
      cout << TEST_HEADER_1 << "직접 변경 엔트리를 생성하여 변경" 
           << endl;
      e.clear();
      cout << "변경 내역: ";
      cout << "st를 삭제, ";
      LdapAttribute attr("st", "");
      attr.setMode(LDAP_MOD_DELETE);
      e.push_back(attr);

      cout << "description에 '호호호'를 추가, ";
      attr.clear();
      attr.setAttrName("description");
      attr.push_back("호호호");
      attr.setMode(LDAP_MOD_ADD);
      e.push_back(attr);

      cout << "seealso를 '정말로'로 변경";
      attr.clear();
      attr.setAttrName("seealso");
      attr.push_back("정말로");
      attr.setMode(LDAP_MOD_REPLACE);
      e.push_back(attr);

      e.ldapModifyAttribute(0, info);
      cout << endl << endl;

      cout << "변경 후 LDAP에서 가져온 엔트리: " << endl;

      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << ": " 
           << "엔트리 이동" << endl;
      cout << "-test_child1 및에 test_child3엔트리 추가" << endl;
      e.clear();
      e.setDn(string("ou=test_child3, ou=test_child1, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child3", ""));
      e.ldapAdd(0, info);
      cout << "추가된 엔트리: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;

      cout << "-위의 엔트리를 test_child2로 이동" << endl;
      string dn3 = string("ou=test_child3, ou=test_child2, ") + testDn;
      LdapEntry::ldapMove(e.getDn(), dn3, 0, info);
      e.ldapFromServer(dn3, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << ": " 
           << "엔트리 하위노드까지 복사" << endl;
      cout << "-test_child2 이하의 엔트리 모두 test_child1 밑으로 복사" << endl;
      LdapEntry::ldapCopyRecursively(string("ou=test_child2, ") + testDn, 
        string("ou=test_child2, ou=test_child1, ") + testDn, 0, 
        info);

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA 엔트리 추가" << endl;
      const string caDn = string("cn=testca, ") + testDn;
      e.clear();
      e.setDn(caDn);
      e.push_back(LdapAttribute("objectclass", "top", "person", "pkiCA", 
          ""));
      e.push_back(LdapAttribute("cn", "testca", ""));
      e.push_back(LdapAttribute("sn", "testca", ""));
      e.push_back(LdapAttribute("description", "testca", ""));
      e.ldapAdd(0, info);
      cout << "추가된 엔트리: " << endl;
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA 엔트리에 CA인증서 추가" << endl;
      LdapEntry::setBinaryAttrs("caCertificate");
      LdapEntry::ldapModifyOneAttribute(caDn, "caCertificate", 
          LDAP_MOD_REPLACE, caCertPath, true, true, 0, info);
      e.clear();
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "가져온 인증서 파일 ca_get.cer로 저장" << endl;
      ofstream file("ca_get.cer", ios::binary);
      if (file)
      {
        file.write((*e.getAttribute("caCertificate"))[0].c_str(), 
            (*e.getAttribute("caCertificate"))[0].size());
      }

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA 엔트리에 description attribute remove" << endl;
      LdapEntry::ldapModifyOneAttribute(caDn, "description", 
          LDAP_MOD_DELETE, "", false, false, 0, info);
      e.clear();
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      if (del)
      {
        cout << TEST_HEADER << ": " 
             << "테스트 엔트리 하위노드까지 삭제" << endl;
        LdapEntry::ldapDeleteRecursively(testDn, 0, info);
      }
      ///////////////////////////////////////////////////////////////
      cout << "\n--모든 단계의 테스트를 성공하였습니다." << endl;
      if (!del)
        cout << "명령 인자에 따라 테스트로 추가한 엔트리를 삭제하지 "
                "않았습니다." << endl;
   }
    while (0);
  }
  catch (std::exception &e)
  {
    cerr << "\n## 오류가 발생하였습니다.(" << e.what() << ")" << endl;
    if (del && added)
    {
      try 
      {
        LdapEntry::ldapDeleteRecursively(testDn, 0, info);
      }
      catch (...)
      {
        cerr << "테스트로 추가한 엔트리를 삭제하는 데도 오류가 발생했습니다." 
             << endl;
      }
    }
  }

  return 0;
}

#endif
