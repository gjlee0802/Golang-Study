#include "LdapEntry.hpp"
#include "LoginProfileLDAPConnection.hpp"
#include "LoginProfile.hpp"

namespace Issac
{

using namespace std;

LDAP *LoginProfileLDAPConnection_Connect()
{
  string ip(LoginProfile::get()->getProfile("LDAP", "IP"));
  string binddn(LoginProfile::get()->getProfile("LDAP", "BINDDN"));
  string passwd(LoginProfile::get()->getProfile("LDAP", "PASSWORD"));
  string port(LoginProfile::get()->getProfile("LDAP", "PORT"));

  return LdapEntry::ldapInitAndBind(LDAP_BIND_INFO(ip, atoi(port.c_str()),
     binddn, passwd));
}

LDAP_BIND_INFO LoginProfileLDAPConnection_GetBindInfo()
{
  string ip(LoginProfile::get()->getProfile("LDAP", "IP"));
  string binddn(LoginProfile::get()->getProfile("LDAP", "BINDDN"));
  string passwd(LoginProfile::get()->getProfile("LDAP", "PASSWORD"));
  string port(LoginProfile::get()->getProfile("LDAP", "PORT"));

  return LDAP_BIND_INFO(ip, atoi(port.c_str()), binddn, passwd);
}

}

