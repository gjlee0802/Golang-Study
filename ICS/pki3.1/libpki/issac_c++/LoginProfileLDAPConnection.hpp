/** 
 * @file     LoginProfileLDAPConnection.hpp 
 * 
 * @desc     LoginProfileLDAPConnection 기본 기능을 정의하는 클래스 
 * @author   조현래(hrcho@pentasecurity.com) 
 * @since    2003.4.24 
 * 
 */ 

#ifndef ISSAC_LOGIN_PROFILE_LDAP_CONNECTION 
#define ISSAC_LOGIN_PROFILE_LDAP_CONNECTION 

namespace Issac
{

LDAP *LoginProfileLDAPConnection_Connect(); 
LDAP_BIND_INFO LoginProfileLDAPConnection_GetBindInfo();

}

#endif 

