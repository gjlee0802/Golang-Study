#ifndef ISSAC_LDAP_ENTRY
#define ISSAC_LDAP_ENTRY

#include <string>
#include <vector>

#include "ldap.h"
#include "Exception.hpp"

typedef std::vector<std::string> string_vector;

namespace Issac
{

int AttributeCompare(const std::string &attr1, const std::string &attr2);
int DnCompare(const std::string &dn1, const std::string &dn2);

class LdapException : public Exception
{
public:
  LdapException(const std::string &s = "LdapException") : Exception(s) {}
  LdapException(int c) : Exception(ldap_err2string(c), c) {}
  LdapException(LDAP *ld, int c) : Exception(getLDAPErrorMsg(ld, c), c) {}

  static const std::string getLDAPErrorMsg(LDAP *ld, int c);
};

class LDAP_BIND_INFO
{
public:
  std::string host;
  int port;
  std::string bindDn;
  std::string passwd;

  LDAP_BIND_INFO(const std::string &h = "", int p = 0, 
      const std::string &d = "", const std::string &w = "") 
    : host(h), port(p), bindDn(d), passwd(w)
  {}
};

class LdapEntry;

class LdapAttribute : public string_vector
{
private:
  std::string _attrName;      /**< attribute name */
  int _mod;

public:
  LdapAttribute();
  LdapAttribute(const char *attrName, ...);

  /**< m_mod를 리턴 */
  int getMode() const { return _mod; }
  void setMode(int mod);
  /**< 어트리븃 이름을 set */
  void setAttrName(const std::string &attrName) { _attrName = attrName; }
  /**< 어트리븃 이름을 get */
  std::string getAttrName() const { return _attrName; }

  /** 변경된 attribute을 ldap서버에 적용하기 위해 비교하여 _mod를 할당할 때
    쓰는 함수. 일반 사용자는 쓰지 않는다.
  */
  LdapAttribute compareAttribute(const LdapAttribute &attr) const;
};

typedef std::vector<LdapAttribute> LdapAttributeVector;

class LdapEntry : public LdapAttributeVector
{
private:
  std::string _dn;
  void _decode();
  void _encode();
  static string_vector _binaryAttrNames;
  static string_vector _mustAttrNames;
  static bool _needEncode;

  void _ldapFromMessage(LDAP *ld, LDAPMessage *e);
  static void _ldapCopyRecursively(const std::string &dn, 
      const std::string &fromDn, const std::string &toDn, LDAP *ld);
  static void _ldapDeleteRecursively(const std::string &dn, LDAP *ld);
  static LDAP *_ldapMakeSureConnection(LDAP *ld, const LDAP_BIND_INFO &info);

public:
  LdapEntry();
  LdapEntry(LDAP *ld, LDAPMessage *e);

  static void setEncodeMode(bool encode = true) { _needEncode = encode; } 

  // 주의 대소문자는 유지한 체 ',' 만 보정한다.
  static std::string regulateDn(std::string dn);

  static std::string getParentDn(std::string dn);
  static std::string getRdn(std::string dn);
  static std::string getRdnValue(const std::string &dn);
  static std::string getRdnAttr(const std::string &dn);

  static bool isAttributeBinary(std::string attr);
  static void setBinaryAttrs(const std::string &attr);
  static void clearBinaryAttrs();
  static bool isAttributeMust(const std::string& attr);
  static void setMustAttrs(const std::string &attr);
  static void clearMustAttrs();

  LdapEntry compareEntry(const LdapEntry &entry) const;

  std::string getDesc() const;
  std::string getHtmlDesc() const;
  void print() const;

  void setDn(const std::string &dn);
  std::string getDn() const { return _dn; }

  LdapEntry::iterator getAttribute(const std::string &attr);
  LdapEntry::const_iterator getAttribute(const std::string &attr) const;

  /* ldap operation */
  // init
  static LDAP *ldapInitAndBind(const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  // seach op.
  void ldapFromServer(const std::string &dn, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO(), char **attrs = NULL);
  static void ldapSearchSync(std::vector<LdapEntry> &entries, 
      const std::string &base, int scope,
      const std::string &filter, char **attrs, 
      int attrsonly, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static std::string ldapSearchOneAttr(const std::string &dn, 
      const std::string &attr, 
      LDAP *ld, const LDAP_BIND_INFO &info = LDAP_BIND_INFO(),
      bool binary = false);
  // modify op. not static, need current entry states
  void ldapAdd(LDAP *ld, const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  void ldapModifyAttribute(LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static void ldapMove(const std::string &oldDn, const std::string &newDn, 
      LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static void ldapModifyRdn(const std::string &dn, 
      const std::string &newRdn, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static void ldapDelete(const std::string &dn, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  // recursive op.
  static void ldapCopyRecursively(const std::string &fromDn, 
      const std::string &toDn, 
      LDAP *ld, const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static void ldapDeleteRecursively(const std::string &startDn, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
  static void ldapModifyOneAttribute(const std::string &dn, 
      const std::string &attrName, int mod, 
      std::string content, bool isContentPath, bool binary, LDAP *ld, 
      const LDAP_BIND_INFO &info = LDAP_BIND_INFO());
};

}

#endif

