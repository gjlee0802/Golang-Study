#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>

#include "ServiceAccountMap.hpp"

using namespace Issac;
using namespace std;

int main(int argc, char * const *argv)
{
  try
  {
    LdapEntry::setEncodeMode(1);
    LDAP_BIND_INFO info("192.168.0.33", 1092, "cn=Manager", "12345678");

    ServiceAccountMap::setMapAttr("st");
    int refcount;
    string key = "1234";
    string id, passwd;
    ServiceAccountMap::useradd("o=pentasecurity,c=kr", "sid1", 
        "id1", "passwd1", refcount, key, 0, info);
    cout << refcount << endl;
    ServiceAccountMap::query("o=pentasecurity,c=kr", "sid1", 
        id, passwd, refcount, key, 0, info);
    cout << id << "," << passwd << "," << refcount << endl;

    ServiceAccountMap::useradd("o=pentasecurity,c=kr", "sid2", 
        "id2", "passwd2", refcount, key, 0, info);
    ServiceAccountMap::query("o=pentasecurity,c=kr", "sid2", 
        id, passwd, refcount, key, 0, info);
    cout << id << "," << passwd << "," << refcount << endl;

    ServiceAccountMap::passwd("o=pentasecurity,c=kr", "sid2", 
        "id222", "passwd222", key, 0, info);
    ServiceAccountMap::query("o=pentasecurity,c=kr", "sid2", 
        id, passwd, refcount, key, 0, info);
    cout << id << "," << passwd << "," << refcount << endl;

    string att = 
      LdapEntry::ldapSearchOneAttr("o=pentasecurity,c=kr", "st", 
          0, info);
    cout << att << endl;
    ServiceAccountMap::userdel("o=pentasecurity,c=kr", "sid2", 
        false, refcount, 0, info);
    att = LdapEntry::ldapSearchOneAttr("o=pentasecurity,c=kr", "st", 
          0, info);
    cout << att << endl;
    ServiceAccountMap::userdel("o=pentasecurity,c=kr", "sid1", 
        true, refcount, 0, info);
    att = LdapEntry::ldapSearchOneAttr("o=pentasecurity,c=kr", "st", 
          0, info);
    cout << att << endl;

  }
  catch (exception &e)
  {
    cerr << e.what();
  }
  return 0;
}
