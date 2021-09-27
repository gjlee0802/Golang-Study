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

#define TEST_HEADER   "\n### �׽�Ʈ �ܰ�: "
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
        "������ڷ� ������ ������� �Է��ؾ� �մϴ�." << endl
        << "ldapip, port, binddn, passwd" << endl 
        << "�׽�Ʈ�� �۾� �� ��Ʈ���� �߰��� �θ��� DN" << endl 
        << "�׽�Ʈ�� �۾� �� ��Ʈ���� ou �̸�" << endl 
        << "�׽�Ʈ�� �۾� �� CA ��Ʈ���� objectclass �̸�" << endl 
        << "�׽�Ʈ�� �۾� �� CA �������� ���� ���" << endl 
        << "���͸� ������ utf8 ���ڵ� ���� ����" << endl 
        << "�׽�Ʈ �� �� ��Ʈ�� ��������" << endl;

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
      cout << TEST_HEADER << "�⺻ �Լ� ����" << endl;
      cout << "-AttributeCompare �Լ�:" << endl;
      cout << " tes, TES �񱳰��: " << AttributeCompare("tes", "TES") << endl;
      cout << " tes;binary, TES �񱳰��: " 
           << AttributeCompare("tes;binary", "TES") << endl;
      cout << " test, TES �񱳰��: " 
           << AttributeCompare("test", "TES") << endl;
      cout << " aaa, test;binary �񱳰��: " 
           << AttributeCompare("aaa", "test;binary") << endl;
      cout << "-DnCompare �Լ�:" << endl;
      cout << " 'cn=manager,c=kr', 'cn=Manager, c=kr' �񱳰��: " 
           << DnCompare("cn=manager,c=kr", "cn=Manager, c=kr") << endl;
      cout << " 'cn=mana,c=kr', 'cn=Manager, c=kr' �񱳰��: " 
           << DnCompare("cn=mana,c=kr", "cn=Manager, c=kr") << endl;
      cout << " 'cn=manager,c=kr', 'cn=Mana, c=kr' �񱳰��: " 
           << DnCompare("cn=manager,c=kr", "cn=Mana, c=kr") << endl;
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "�θ� DN �б� �׽�Ʈ" << endl;
      e.ldapFromServer(baseDn, 0, infoAnony);
      cout << e.getDesc();
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "�߸��� DN �б� (��� ����: no such object)" 
           << endl;
      try
      {
        e.ldapFromServer("cn=__bad__dn", 0, infoAnony);
      }
      catch (std::exception &e)
      {
        cout << "���������� �����߻�: " << e.what() << endl;
      }
  
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "��Ʈ�� �߰�" << endl;
      cout << TEST_HEADER_1 << "�׽�Ʈ ��Ʈ �߰�" << endl;
      added = true;
      e.clear();
      e.setDn(testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", LdapEntry::getRdnValue(e.getDn()).c_str(),
          ""));
      e.push_back(LdapAttribute("seeAlso", "see what?", ""));
      e.push_back(LdapAttribute("description", "�׽�Ʈ", ""));
      e.push_back(LdapAttribute("l", "washington, d.c.", ""));
      e.ldapAdd(0, info);
      cout << "�߰��� ��Ʈ��: " << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;
      added = true;

      cout << TEST_HEADER_1 << "�׽�Ʈ ��Ʈ �׿� ��Ʈ�� 1 �߰�" << endl;
      e.clear();
      e.setDn(string("ou=test_child1, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child1", ""));
      e.ldapAdd(0, info);
      cout << "�߰��� ��Ʈ��: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;

      cout << TEST_HEADER_1 << "�׽�Ʈ ��Ʈ �׿� ��Ʈ�� 2 �߰�" << endl;
      e.clear();
      e.setDn(string("ou=test_child2, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child2", ""));
      e.ldapAdd(0, info);
      cout << "�߰��� ��Ʈ��: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;
 
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "��Ʈ�� ���������� �˻�" << endl;
      vector<LdapEntry> entries;
      entries.clear();
      LdapEntry::ldapSearchSync(entries, testDn, LDAP_SCOPE_SUBTREE, 
          "objectclass=*", NULL, 0, NULL, info); 
      cout << entries.size() << " �� �˻�" << endl;
      for_each(entries.begin(), entries.end(), mem_fun_ref(&LdapEntry::print));
 
      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "��Ʈ�� ����" << endl;
      cout << TEST_HEADER_1 << "�� ��ü�� �񱳸� ���� ����" << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      LdapEntry eMod = e;
      cout << "������: " << endl;
      cout << eMod.getDesc() << endl;

      cout << "���� ����: description�� 'test'�� 'test2' �߰�, "
              "seealso�� '�Ⱥ���'�� ����, l�� ����, st�� rodeo�� �־ �߰�"
           << endl;
      eMod.getAttribute("description")->push_back("test");
      eMod.getAttribute("description")->push_back("test2");
      (*(eMod.getAttribute("seealso")))[0] = "�Ⱥ���";
      eMod.erase(eMod.getAttribute("l"));
      eMod.push_back(LdapAttribute("st", "rodeo", ""));

      cout << "ldapModifyAttribute ����" << endl;
      LdapEntry eNew = e.compareEntry(eMod);
      eNew.ldapModifyAttribute(0, info);

      cout << "���� �� LDAP���� ������ ��Ʈ��: " << endl;
      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;
  
      cout << TEST_HEADER_1 << "���� ���� ��Ʈ���� �����Ͽ� ����" 
           << endl;
      e.clear();
      cout << "���� ����: ";
      cout << "st�� ����, ";
      LdapAttribute attr("st", "");
      attr.setMode(LDAP_MOD_DELETE);
      e.push_back(attr);

      cout << "description�� 'ȣȣȣ'�� �߰�, ";
      attr.clear();
      attr.setAttrName("description");
      attr.push_back("ȣȣȣ");
      attr.setMode(LDAP_MOD_ADD);
      e.push_back(attr);

      cout << "seealso�� '������'�� ����";
      attr.clear();
      attr.setAttrName("seealso");
      attr.push_back("������");
      attr.setMode(LDAP_MOD_REPLACE);
      e.push_back(attr);

      e.ldapModifyAttribute(0, info);
      cout << endl << endl;

      cout << "���� �� LDAP���� ������ ��Ʈ��: " << endl;

      e.ldapFromServer(testDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << ": " 
           << "��Ʈ�� �̵�" << endl;
      cout << "-test_child1 �׿� test_child3��Ʈ�� �߰�" << endl;
      e.clear();
      e.setDn(string("ou=test_child3, ou=test_child1, ") + testDn);
      e.push_back(LdapAttribute("objectclass", "top", "organizationalUnit", 
          ""));
      e.push_back(LdapAttribute("ou", "test_child3", ""));
      e.ldapAdd(0, info);
      cout << "�߰��� ��Ʈ��: " << endl;
      e.ldapFromServer(e.getDn(), 0, infoAnony);
      cout << e.getDesc() << endl;

      cout << "-���� ��Ʈ���� test_child2�� �̵�" << endl;
      string dn3 = string("ou=test_child3, ou=test_child2, ") + testDn;
      LdapEntry::ldapMove(e.getDn(), dn3, 0, info);
      e.ldapFromServer(dn3, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << ": " 
           << "��Ʈ�� ���������� ����" << endl;
      cout << "-test_child2 ������ ��Ʈ�� ��� test_child1 ������ ����" << endl;
      LdapEntry::ldapCopyRecursively(string("ou=test_child2, ") + testDn, 
        string("ou=test_child2, ou=test_child1, ") + testDn, 0, 
        info);

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA ��Ʈ�� �߰�" << endl;
      const string caDn = string("cn=testca, ") + testDn;
      e.clear();
      e.setDn(caDn);
      e.push_back(LdapAttribute("objectclass", "top", "person", "pkiCA", 
          ""));
      e.push_back(LdapAttribute("cn", "testca", ""));
      e.push_back(LdapAttribute("sn", "testca", ""));
      e.push_back(LdapAttribute("description", "testca", ""));
      e.ldapAdd(0, info);
      cout << "�߰��� ��Ʈ��: " << endl;
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA ��Ʈ���� CA������ �߰�" << endl;
      LdapEntry::setBinaryAttrs("caCertificate");
      LdapEntry::ldapModifyOneAttribute(caDn, "caCertificate", 
          LDAP_MOD_REPLACE, caCertPath, true, true, 0, info);
      e.clear();
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "������ ������ ���� ca_get.cer�� ����" << endl;
      ofstream file("ca_get.cer", ios::binary);
      if (file)
      {
        file.write((*e.getAttribute("caCertificate"))[0].c_str(), 
            (*e.getAttribute("caCertificate"))[0].size());
      }

      ///////////////////////////////////////////////////////////////
      cout << TEST_HEADER << "CA ��Ʈ���� description attribute remove" << endl;
      LdapEntry::ldapModifyOneAttribute(caDn, "description", 
          LDAP_MOD_DELETE, "", false, false, 0, info);
      e.clear();
      e.ldapFromServer(caDn, 0, infoAnony);
      cout << e.getDesc() << endl;

      ///////////////////////////////////////////////////////////////
      if (del)
      {
        cout << TEST_HEADER << ": " 
             << "�׽�Ʈ ��Ʈ�� ���������� ����" << endl;
        LdapEntry::ldapDeleteRecursively(testDn, 0, info);
      }
      ///////////////////////////////////////////////////////////////
      cout << "\n--��� �ܰ��� �׽�Ʈ�� �����Ͽ����ϴ�." << endl;
      if (!del)
        cout << "��� ���ڿ� ���� �׽�Ʈ�� �߰��� ��Ʈ���� �������� "
                "�ʾҽ��ϴ�." << endl;
   }
    while (0);
  }
  catch (std::exception &e)
  {
    cerr << "\n## ������ �߻��Ͽ����ϴ�.(" << e.what() << ")" << endl;
    if (del && added)
    {
      try 
      {
        LdapEntry::ldapDeleteRecursively(testDn, 0, info);
      }
      catch (...)
      {
        cerr << "�׽�Ʈ�� �߰��� ��Ʈ���� �����ϴ� ���� ������ �߻��߽��ϴ�." 
             << endl;
      }
    }
  }

  return 0;
}

#endif
