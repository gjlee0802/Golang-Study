/*********************************************************************

  filename :  LdapEntry.cpp

  author : Cho, Hyeon Rae (hrcho@pentasecurity.com)
  company : Penta Security Systems Inc.
  date : 2003/03/25
  version : 2.00
  dependency : cis 모듈의 charset.h와 관련 lib을 필요로 한다.

 *********************************************************************/

#ifdef _WIN32
#include <Windows.h>
#else
#include <strings.h>
#ifndef stricmp
#define stricmp(a, b) strcasecmp((a), (b))
#endif
#endif

#include <stdarg.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <boost/scoped_array.hpp>
#include <boost/shared_ptr.hpp>

#include "charset.h"

#include "LdapEntry.hpp"
#include "Trace.h"

#define TMPLOG "/tmp/libpki.log"

const char *ATTR_OBJECTCLASS = "objectClass";
const char *RDN_DELIMITER = ", ";
const char *LDAP_ENTRY_MEMORY_ERROR = "LdapException: memory allocation error";

const int MAX_DN_LEN = 1000;

using namespace std;

namespace Issac
{

const string LdapException::getLDAPErrorMsg(LDAP *ld, int c)
{
  assert(ld);

  ostringstream ost;
  ost << ldap_err2string(c);
  char *errorMsg = NULL;
  ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &errorMsg);
  if (errorMsg != NULL)
  {
    if (*errorMsg != '\0') ost << " (" << errorMsg << ')';
    ldap_memfree(errorMsg);
  }

  return ost.str();
}

int AttributeCompare(const string &attr1, const string &attr2)
{
  string::size_type pos;
  string a1, a2;

  if ((pos = attr1.find(";")) != string::npos)
    a1 = attr1.substr(0, pos);
  else
    a1 = attr1;

  if ((pos = attr2.find(";")) != string::npos)
    a2 = attr2.substr(0, pos);
  else
    a2 = attr2;

  return stricmp(a1.c_str(), a2.c_str());
}

int DnCompare(const string &dn1, const string &dn2)
{
  string d1 = LdapEntry::regulateDn(dn1);
  string d2 = LdapEntry::regulateDn(dn2);

  return stricmp(d1.c_str(), d2.c_str());
}

// class LdapAttribute

LdapAttribute::LdapAttribute()
{
}

void LdapAttribute::setMode(int mod)
{
  _mod = mod | LDAP_MOD_BVALUES;
}

LdapAttribute::LdapAttribute(const char *attrName, ...)
{
  va_list values;
  char *val;

  _attrName = attrName;
  va_start(values, attrName);

  while (val = (char *)va_arg(values, char*), (val != 0 && *val != 0))
    push_back(val);

  va_end(values);
}

/* FIXME - 복수개의 값처리에 문제가 있다. */
LdapAttribute LdapAttribute::compareAttribute(const LdapAttribute &attr) const
{
  const_iterator it1, it2;
  bool flag = true;
  for (it1 = attr.begin(); it1 != attr.end(); ++it1)
  {
    for (it2 = this->begin(); it2 != this->end(); ++it2)
    {
      if (it1->compare(*it2) == 0)
        break;
    }
    if (it2 == this->end())
    {
      flag = false;
      break;
    }
  }

  LdapAttribute ret;
  if (!flag)
  {
    ret = attr;
    ret.setMode(LDAP_MOD_REPLACE);
  }

  return ret;
}

// class LdapEntry

// Active Directory 같은 경우는 서버가 인코딩/디코딩을 해주므로
// 어플리케이션에서 할 필요가 없다.
// 그 외의 디렉토리는 인코딩/디코딩을 어플리케이션에서 해주어야 한다.
bool LdapEntry::_needEncode = true;
string_vector LdapEntry::_binaryAttrNames;
string_vector LdapEntry::_mustAttrNames;

LdapEntry::LdapEntry()
{
}

LdapEntry::LdapEntry(LDAP *ld, LDAPMessage *e)
{
  _ldapFromMessage(ld, e);
}

LdapEntry::iterator LdapEntry::getAttribute(const string &attrName)
{
  for (LdapEntry::iterator i = begin(); i != end(); ++i)
  {
    if (!AttributeCompare(i->getAttrName(), attrName))
    {
      return i;
    }
  }
  return end();
}

LdapEntry::const_iterator LdapEntry::getAttribute(const string &attrName) const
{
  for (LdapEntry::const_iterator i = begin(); i != end(); ++i)
  {
    if (!AttributeCompare(i->getAttrName(), attrName))
    {
      return i;
    }
  }
  return end();
}

void LdapEntry::_ldapFromMessage(LDAP *ld, LDAPMessage *e)
{
  char       *dn, *attr;
  BerElement *ber;

  if ((dn = ldap_get_dn(ld, e)) != NULL)
  {
    setDn(dn);
    ldap_memfree(dn);
  }
  for (attr = ldap_first_attribute(ld, e, &ber); attr != NULL; 
       attr = ldap_next_attribute(ld, e, ber))
  {
    struct berval **bvals;
    if ((bvals = ldap_get_values_len(ld, e, attr)) != NULL)
    {
      LdapAttribute a;
      a.setAttrName(attr);
      for (int i = 0; bvals[i] != NULL; ++i)
      {
        a.push_back(string(bvals[i]->bv_val, bvals[i]->bv_len));
      }
      push_back(a);
      ber_bvecfree(bvals);
    }
  }
  if (ber != NULL) 
  {
    ber_free(ber, 0);
  }

  _decode();
}

void LdapEntry::setDn(const string &dn)
{ 
  _dn = dn;
}

string LdapEntry::regulateDn(string dn)
{
  int pos = 1;

  while ((pos = dn.find(",", pos)) != -1)
  {
    if (pos < (signed)dn.size() - 1 && dn[pos + 1] != ' ' 
        && dn[pos - 1] != '\\')
      dn.insert(pos + 1, " ");
    ++pos;
  }
  return dn;
}

string LdapEntry::getParentDn(string dn)
{
  int pos = 1;

  while ((pos = dn.find(",", pos)) != -1)
  {
    if (pos < (signed)dn.size() - 1 && dn[pos + 1] != ' ' 
        && dn[pos - 1] != '\\')
      dn.insert(pos + 1, " ");
    ++pos;
  }

  pos = 1;

  while ((pos = dn.find(RDN_DELIMITER, pos)) != -1)
  {
    if (dn[pos - 1] != '\\')
      return dn.substr(pos + strlen(RDN_DELIMITER));
    pos = pos + strlen(RDN_DELIMITER);
  }
  return string("");
}

string LdapEntry::getRdn(string dn)
{
  int pos = 1;

  while ((pos = dn.find(",", pos)) != -1)
  {
    if (pos < (signed)dn.size() - 1 && dn[pos + 1] != ' ' 
        && dn[pos - 1] != '\\')
      dn.insert(pos + 1, " ");
    ++pos;
  }

  pos = 1;

  while ((pos = dn.find(RDN_DELIMITER, pos)) != -1)
  {
    if (dn[pos - 1] != '\\')
      return dn.substr(0, pos);
    pos = pos + strlen(RDN_DELIMITER);
  }
  return dn;
}

string LdapEntry::getRdnValue(const string &dn)
{
  const string rdn(getRdn(dn));
  return rdn.substr(rdn.find("=") + 1);
}

string LdapEntry::getRdnAttr(const string &dn)
{
  const string rdn(getRdn(dn));
  return rdn.substr(0, rdn.find("="));
}

/**
 * CreateLDAPModArray로 부터 얻은 LDAPModArray를 지운다.
 */
void DeleteLDAPModArray(LDAPMod **mods)
{
  int i;
  for (i = 0; mods[i] != NULL; ++i)
  {
    berval **bervalPtr = reinterpret_cast<berval **>(mods[i]->mod_values);
    int j;
    for (j = 0; bervalPtr[j] != NULL; ++j)
    {
      delete[] bervalPtr[j]->bv_val;
      delete bervalPtr[j];
    }
    delete[] bervalPtr;
    delete[] mods[i]->mod_type;
    delete mods[i];
  }
  delete[] mods;
}

/**
 * @brief LdapEntry로 부터 LDAPMod array를 얻는다.
 */
static LDAPMod **CreateLDAPModArray(const LdapEntry& entry)
{
  LDAPMod **mods = new LDAPMod *[entry.size() + 1];

  int i;
  for (i = 0; i < (signed)entry.size(); ++i)
  {
    mods[i] = new LDAPMod;
    // DeleteLDAPModArray(mods);

    mods[i]->mod_type = new char[entry[i].getAttrName().size() + 1];
    ::strcpy(mods[i]->mod_type, entry[i].getAttrName().c_str());

    berval **p_berval = new berval *[entry[i].size() + 1];
    int j;
    for (j = 0; j < (signed)entry[i].size(); ++j)
    {
      p_berval[j] = new berval;
      p_berval[j]->bv_len = entry[i][j].size();
      p_berval[j]->bv_val = new char[p_berval[j]->bv_len + 1];
      ::memcpy(p_berval[j]->bv_val, entry[i][j].c_str(), entry[i][j].size());
    }
    p_berval[j] = NULL;
    mods[i]->mod_values = reinterpret_cast<char **>(p_berval);
  }
  mods[i] = NULL;

  return mods;
}

LDAP *LdapEntry::_ldapMakeSureConnection(LDAP *ld, const LDAP_BIND_INFO &info)
{
  if (!ld)
    return ldapInitAndBind(info);
  else 
    return ld;
}

void LdapEntry::ldapAdd(LDAP *ld, const LDAP_BIND_INFO &info)
{
  int      nmods = size();
  boost::shared_ptr<LDAPMod *> mods;
  int      i;
  LDAP *ldap = _ldapMakeSureConnection(ld, info);
  int      ret;

  _encode();

  /* construct the array of values to add */
  try
  {
    mods.reset(CreateLDAPModArray(*this), DeleteLDAPModArray);;
  }
  catch (...)
  {
    _decode();

    if (!ld)
      ldap_unbind(ldap);

    throw LdapException(LDAP_ENTRY_MEMORY_ERROR);
  }

  for (i = 0; i < nmods; ++i)
    mods.get()[i]->mod_op = LDAP_MOD_ADD|LDAP_MOD_BVALUES;

  ret = ldap_add_s(ldap, _dn.c_str(), mods.get());

  if (ret != LDAP_SUCCESS)
  {
    _decode();

    const LdapException e(ldap, ret);

    if (!ld)
      ldap_unbind(ldap);

    throw e;
  }

  if (!ld) 
    ldap_unbind(ldap);

 _decode();
}

LDAP *LdapEntry::ldapInitAndBind(const LDAP_BIND_INFO &info)
{
  int ret;
  LDAP *ldap = NULL;
  // ldap init
  if ((ldap = ldap_init(info.host.c_str(), info.port)) == NULL)
  {
    throw LdapException(LDAP_CONNECT_ERROR);
  }

  // ldap bind
  char bindDnEncoded[MAX_DN_LEN];
  char *binddn = NULL;
  char *passwd = NULL;

  if (_needEncode && !info.bindDn.empty())
  {
    int  outlen;

    CHARSET_EuckrToUtf8((unsigned char *)bindDnEncoded, &outlen, 
        (const unsigned char *)info.bindDn.c_str());
    binddn = bindDnEncoded;
  }
  else
  {
    if (!info.bindDn.empty())
      binddn = const_cast<char *>(info.bindDn.c_str());
    else
      binddn = NULL;
  }

  if (!info.passwd.empty())
    passwd = const_cast<char *>(info.passwd.c_str());
  else
    passwd = NULL;

  ret = ldap_simple_bind_s(ldap, binddn, passwd);
  if (ret != LDAP_SUCCESS)
  {
    const LdapException e(ldap, ret);

    ldap_unbind(ldap);

    throw e;
  }
  int version = LDAP_VERSION3;
  ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version); 
  return ldap;
}

void LdapEntry::ldapDelete(const string &dn, LDAP *ld, 
    const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);
  int  ret;

  if (_needEncode == true)
  {
    char dnEncoded[MAX_DN_LEN];
    int  outlen;
    CHARSET_EuckrToUtf8((unsigned char *)dnEncoded, &outlen, 
      (const unsigned char *)dn.c_str());
    ret = ldap_delete_s(ldap, (char *)dnEncoded);
  }
  else
  {
    ret = ldap_delete_s(ldap, (char *)dn.c_str());
  }

  if (ret != LDAP_SUCCESS)
  {
    const LdapException e(ldap, ret);

    if (!ld)
      ldap_unbind(ldap);

    throw e;
  }

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::ldapModifyAttribute(LDAP *ld, const LDAP_BIND_INFO &info)
{
  int      nmods = size();
  boost::shared_ptr<LDAPMod *> mods;
  int      i = 0, ret;
  LDAP *ldap = _ldapMakeSureConnection(ld, info);

  _encode();

  try
  {
    mods.reset(CreateLDAPModArray(*this), DeleteLDAPModArray);;
  }
  catch (...)
  {
    _decode();

    if (!ld) 
      ldap_unbind(ldap);

    throw LdapException(LDAP_ENTRY_MEMORY_ERROR);
  }

  for (i = 0; i < nmods; ++i)
    mods.get()[i]->mod_op = (*this)[i].getMode();

  /* make the change */
  ret = ldap_modify_s(ldap, _dn.c_str(), mods.get());

  if (ret != LDAP_SUCCESS) 
  {
    _decode();

    const LdapException e(ldap, ret);

    if (!ld) 
      ldap_unbind(ldap);

    throw e;
  }

  if (!ld) ldap_unbind(ldap);

  _decode();
}

void LdapEntry::ldapModifyRdn(const string &dn, const string &newRdn, LDAP *ld, 
    const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);
  int  ret;

  /* Do the modrdn operation */
  if (_needEncode == true)
  {
    int  outlen;

    char dnEncoded[MAX_DN_LEN];
    CHARSET_EuckrToUtf8((unsigned char *)dnEncoded, &outlen, 
      (const unsigned char *)dn.c_str());

    char newRdnEncoded[MAX_DN_LEN];
    CHARSET_EuckrToUtf8((unsigned char *)newRdnEncoded, &outlen, 
      (const unsigned char *)newRdn.c_str());

    ret = ldap_modrdn2_s(ldap, dnEncoded, newRdnEncoded, 1);
  }
  else
  {
    ret = ldap_modrdn2_s(ldap, dn.c_str(), newRdn.c_str(), 1);
  }

  if (ret != LDAP_SUCCESS)
  {
    const LdapException e(ldap, ret);

    if (!ld)
      ldap_unbind(ldap);

    throw e;
  }

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::ldapMove(const std::string &oldDn, const string &newDn, 
    LDAP *ld, const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);

  /* Do the move operation */
  LdapEntry e;
  e.ldapFromServer(oldDn, ldap, info);
  try
  {
    ldapDelete(e.getDn(), ldap);
  }
  catch (...)
  {
    if (!ld)
      ldap_unbind(ldap);

    throw;
  }

  e.setDn(newDn);
  try
  {
    e.ldapAdd(ldap);
  }
  catch (...)
  {
    e.setDn(oldDn);
    e.ldapAdd(ldap);

    if (!ld)
      ldap_unbind(ldap);

    throw;
  }

  if (!ld)
    ldap_unbind(ldap);
}

LdapEntry LdapEntry::compareEntry(const LdapEntry &entry) const
{
  LdapEntry entryMod;
  LdapEntry::const_iterator attrFound;
  LdapAttribute attrMod;
  const string rdnAttr(LdapEntry::getRdnAttr(entry.getDn()));

  entryMod.setDn(entry.getDn().c_str());
  const_iterator i;
  for (i = begin(); i != end(); ++i)
  {
    /* objectclass등의 속성은 삭제하거나 변경하지 말자 */
    if (isAttributeMust(i->getAttrName()))
      continue;

    if ((attrFound = entry.getAttribute(i->getAttrName())) == 
      entry.end() || attrFound->empty())
      // FIXME - empty() 부분으로 삭제 여부를
      // 판단할 수는 없고, 사실은 삭제된 어트리븃이 추가되어야 한다.
    {
      LdapAttribute attr;
      attr.setMode(LDAP_MOD_DELETE);
      attr.setAttrName(i->getAttrName());
      entryMod.push_back(attr);
    }
    else
    {
      attrMod = i->compareAttribute(*attrFound);
      if ((attrMod.getMode() & LDAP_MOD_REPLACE) == LDAP_MOD_REPLACE 
          && rdnAttr != attrMod.getAttrName())
      {
        entryMod.push_back(attrMod);
      }
    }
  }
  for (i = entry.begin(); i != entry.end(); ++i)
  {
    /* objectclass등의 속성은 삭제하거나 변경하지 말자 */
    if (isAttributeMust(i->getAttrName()))
      continue;

    if ((attrFound = getAttribute(i->getAttrName().c_str())) == end())
    {
      LdapAttribute attr = *i;
      attr.setMode(LDAP_MOD_ADD);
      entryMod.push_back(attr);
    }
    else if (attrFound->empty())
    {
      LdapAttribute attr = *i;
      attr.setMode(LDAP_MOD_ADD);
      entryMod.push_back(attr);
    }
  }

  return entryMod;
}

string LdapEntry::getDesc() const
{
  string content("dn: ");
  content += _dn.c_str();
  content += "\n";

  for (const_iterator e = begin() ; e != end(); ++e)
  {
    if (isAttributeBinary(e->getAttrName()))
    {
      content += e->getAttrName();
      content += ": (binary)\n";
      continue;
    }
    if (!e->getAttrName().empty() && e->empty())
    {
      content += e->getAttrName();
      content += ": (null)\n";
      continue;
    }

    for (LdapAttribute::const_iterator a = e->begin(); 
      a != e->end(); ++a)
    {
      content += e->getAttrName();
      content += ": ";
      content += *a;
      content += "\n";
    }
  }
  content += "\n";
  return content;
}

string LdapEntry::getHtmlDesc() const
{
  string content("<html>\n"
    "<head>\n"
    "<title>");
  content += _dn;
  content += "</title>\n"
    "</head>\n"
    "\n"
    "<body>\n"
    "<font face=Arial size=2>\n";

  content += "<p><b>dn</b>\n"
    ": ";
  content += _dn;

  for (const_iterator e = begin() ; e != end(); ++e)
  {
    if (!e->getAttrName().empty() && e->empty())
    {
      content += "<br><b>";
      content += e->getAttrName();
      content += "</b>\n";
      content += ": ";
      content += "(null)";
      content += "\n";
      continue;
    }
    if (isAttributeBinary(e->getAttrName()))
    {
      content += "<br><b>";
      content += e->getAttrName();
      content += "</b>\n";
      content += ": ";
      content += "(binary)";
      content += "\n";
      continue;
    }
    for (LdapAttribute::const_iterator a = e->begin(); a != e->end(); ++a)
    {
      content += "<br><b>";
      content += e->getAttrName();
      content += "</b>\n";
      content += ": ";
      content += *a;
      content += "\n";
    }
  }
  content += "</font>\n"
    "</body>\n"
    "\n"
    "</html>\n";

  return content;
}

void LdapEntry::print() const
{
  cout << getDesc() << endl;
}

void LdapEntry::_encode()
{
  if (_needEncode == false)
    return;

  int  outlen;

  boost::scoped_array<char> buf;
  buf.reset(new char[_dn.size() * 2 + 1]);
  CHARSET_EuckrToUtf8((unsigned char *)buf.get(), &outlen, 
    (const unsigned char *)_dn.c_str());
  _dn = buf.get();

  for (iterator e = begin() ; e != end(); ++e)
  {
    /* 바이너리는 인코딩 디코딩에서 제외한다. */
    if (isAttributeBinary(e->getAttrName()))
      continue;

    for (LdapAttribute::iterator a = e->begin(); a != e->end(); ++a)
    {
      buf.reset(new char[a->size() * 2 + 1]);
      CHARSET_EuckrToUtf8((unsigned char *)buf.get(), &outlen, 
        (const unsigned char *)a->c_str());
      *a = string(buf.get(), outlen);
    }
  }
}

void LdapEntry::_decode()
{
  if (_needEncode == false)
    return;

  int  outlen;
  boost::scoped_array<char> buf;
  buf.reset(new char[_dn.size() * 2 + 1]);

  CHARSET_Utf8ToEuckr((unsigned char *)buf.get(), &outlen, 
    (const unsigned char *)_dn.c_str());
  _dn = buf.get();

  for (iterator e = begin() ; e != end(); ++e)
  {
    /* 바이너리는 인코딩 디코딩에서 제외한다. */
    if (isAttributeBinary(e->getAttrName()))
      continue;

    for (LdapAttribute::iterator a = e->begin(); a != e->end(); ++a)
    {
      // 디코딩할 땐 작아지니 2를 곱하지 않고...
      buf.reset(new char[a->size() + 1]);
      CHARSET_Utf8ToEuckr((unsigned char *)buf.get(), &outlen, 
        (const unsigned char *)a->c_str());
      *a = string(buf.get(), outlen);
    }
  }
}

void LdapEntry::ldapFromServer(const string &dn, LDAP *ld, const LDAP_BIND_INFO &info, char **attrs)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);
  LDAPMessage *result;
  int ret;

  if (_needEncode == true)
  {
    char dnEncoded[MAX_DN_LEN];
    int  outlen;

    CHARSET_EuckrToUtf8((unsigned char *)dnEncoded, &outlen, 
      (const unsigned char *)dn.c_str());

    ret = ldap_search_s(ldap, dnEncoded, LDAP_SCOPE_BASE,
      "objectclass=*", attrs, 0, &result);
  }
  else
  {
    ret = ldap_search_s(ldap, dn.c_str(), LDAP_SCOPE_BASE,
            "objectclass=*", attrs, 0, &result);
  }
  if (ret != LDAP_SUCCESS) 
  {
    const LdapException e(ldap, ret);

    if (!ld)
      ldap_unbind(ldap);

    throw e;
  }

  LDAPMessage *e;
  // 루프를 돌지만 성공해야 하나이다.
  for (e = ldap_first_entry(ldap, result); e != NULL; 
    e = ldap_next_entry(ldap, e))
  {
    clear();
    setDn(dn);
    _ldapFromMessage(ldap, e);
  }
  ldap_msgfree(result);

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::setBinaryAttrs(const string& attr)
{
  if (!isAttributeBinary(attr))
    _binaryAttrNames.push_back(attr);
}

void LdapEntry::clearBinaryAttrs()
{
  _binaryAttrNames.clear();
}

void LdapEntry::setMustAttrs(const string& attr)
{
  if (!isAttributeMust(attr))
  _mustAttrNames.push_back(attr);
}

void LdapEntry::clearMustAttrs()
{
  _mustAttrNames.clear();
}

bool LdapEntry::isAttributeMust(const string& attr)
{
  if (!AttributeCompare(attr, ATTR_OBJECTCLASS))
    return true;

  if (!_mustAttrNames.empty())
  {
    for (string_vector::iterator i = _mustAttrNames.begin(); 
      i != _mustAttrNames.end(); ++i)
    {
      if (!AttributeCompare(attr, *i))
        return true;
    }
  }
  return false;
}

bool LdapEntry::isAttributeBinary(string attr)
{
  transform(attr.begin(), attr.end(), attr.begin(), ::tolower);

  if (attr.find(";binary") != string::npos)
    return true;
  if (attr.find("certificate") != string::npos)
    return true;
  if (attr.find("revocation") != string::npos)
    return true;

  if (!_binaryAttrNames.empty())
  {
    for (string_vector::iterator i = _binaryAttrNames.begin(); 
      i != _binaryAttrNames.end(); ++i)
    {
      if (!AttributeCompare(attr, *i))
        return true;
    }
  }
  return false;
}

static const string ModifyDnForMoving(const string& dn, const string& fromDn, 
  const string& toDn)
{
  string dnReg(LdapEntry::regulateDn(dn));
  string fromDnReg(LdapEntry::regulateDn(fromDn));
  string toDnReg(LdapEntry::regulateDn(toDn));

  transform(dnReg.begin(), dnReg.end(), dnReg.begin(), ::tolower);
  transform(fromDnReg.begin(), fromDnReg.end(), fromDnReg.begin(), ::tolower);
  transform(toDnReg.begin(), toDnReg.end(), toDnReg.begin(), ::tolower);

  int pos;
  if ((pos = dnReg.find(fromDnReg)) == -1)
    throw LdapException(string("can't modify dn for moving: ") + dn);

  dnReg = LdapEntry::regulateDn(dn);
  toDnReg = LdapEntry::regulateDn(toDn);
  return dnReg.substr(0, pos) + toDnReg;
}

void LdapEntry::_ldapCopyRecursively(const string &dn, const string &fromDn, 
  const string &toDn, LDAP *ld)
{
  LdapEntry e;
  e.ldapFromServer(dn, ld);

  // 자신을 넣고
  const string sdn(ModifyDnForMoving(dn, fromDn, toDn));

  e.setDn(sdn.c_str());
  TRACE_LOG(TMPLOG, "copying '%s' to '%s'", dn.c_str(), sdn.c_str());
  e.ldapAdd(ld);

  // 자식을 검색
  vector<LdapEntry> entries;
  ldapSearchSync(entries, dn, LDAP_SCOPE_ONELEVEL, "objectclass=*", 
    NULL, 0, ld);

  vector<LdapEntry>::iterator itr;
  for (itr = entries.begin(); itr != entries.end(); ++itr)
  {
    _ldapCopyRecursively(itr->getDn(), fromDn, toDn, ld);
  }
}

void LdapEntry::ldapCopyRecursively(const string &fromDn, const string &toDn, LDAP *ld, 
    const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);

  _ldapCopyRecursively(fromDn, fromDn, toDn, ldap);

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::ldapDeleteRecursively(const string &startDn, LDAP *ld, 
    const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);

  _ldapDeleteRecursively(startDn, ldap);

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::_ldapDeleteRecursively(const string &dn, LDAP *ld)
{
  vector<LdapEntry> entries;
  ldapSearchSync(entries, dn, LDAP_SCOPE_ONELEVEL, "objectclass=*", 
    NULL, 0, ld);

  vector<LdapEntry>::iterator itr;
  for (itr = entries.begin(); itr != entries.end(); ++itr)
  {
    _ldapDeleteRecursively(itr->getDn(), ld);
  }
  ldapDelete(dn, ld);
}

void LdapEntry::ldapSearchSync(vector<LdapEntry> &entries, const string &base, 
    int scope, const string &filter, char **attrs, int attrsonly, LDAP *ld, 
    const LDAP_BIND_INFO &info)
{
  LDAP *ldap = _ldapMakeSureConnection(ld, info);
  LDAPMessage *result;
  int         ret;

  if (_needEncode == true)
  {
    char buf[MAX_DN_LEN];
    int  outlen;

    CHARSET_EuckrToUtf8((unsigned char *)buf, &outlen, 
      (const unsigned char *)base.c_str());
    const string baseEncoded(buf);
    CHARSET_EuckrToUtf8((unsigned char *)buf, &outlen, 
      (const unsigned char *)filter.c_str());
    const string filterEncoded(buf);

    ret = ldap_search_s(ldap, baseEncoded.c_str(), scope, 
      filterEncoded.c_str(), attrs, attrsonly, &result);
  }
  else
  {
    ret = ldap_search_s(ldap, base.c_str(), scope, filter.c_str(), attrs, 
      attrsonly, &result);
  }
  
  if (ret != LDAP_SUCCESS) 
  {
    const LdapException e(ldap, ret);

    if (!ld)
      ldap_unbind(ldap);

    throw e;
  }

  LDAPMessage *e;

  for (e = ldap_first_entry(ldap, result); 
    e != NULL; e = ldap_next_entry(ldap, e))
  {
    LdapEntry entry(ldap, e);
    entries.push_back(entry);
  }

  ldap_msgfree(result);

  if (!ld)
    ldap_unbind(ldap);
}

void LdapEntry::ldapModifyOneAttribute(const string &dn, 
    const string &attrName, int mod, string content, bool isContentPath, 
    bool binary, LDAP *ld, const LDAP_BIND_INFO &info)
{
  if (binary)
    setBinaryAttrs(attrName);

  if (!(mod & LDAP_MOD_DELETE) && isContentPath)
  {
    ifstream file(content.c_str(), ios::binary);

    if (!file)

      throw LdapException(content + ": can't open file");
  
    file.seekg(0, ios::end);
		streampos len = file.tellg();
    file.seekg(0, ios::beg);
    if (len)
    {
      boost::scoped_array<char> buf(new char[len]);
      file.read(buf.get(), len);
      content = string(buf.get(), len);
    }
  }
  LdapEntry e; e.setDn(dn);

  LdapAttribute a; a.setAttrName(attrName); 
  if (!(mod & LDAP_MOD_DELETE))
    a.push_back(content);
  a.setMode(mod);

  e.push_back(a);
  e.ldapModifyAttribute(ld, info);
}

string LdapEntry::ldapSearchOneAttr(const string &dn, const string &attr, 
    LDAP *ld, const LDAP_BIND_INFO &info, bool binary)

{
  if (binary)
    setBinaryAttrs(attr);

  char *attrs[2] = { (char *)(attr.c_str()), NULL };
  LdapEntry e;
  e.ldapFromServer(dn, ld, info, attrs);
  if (!e.empty() && !e.begin()->empty())
    return e.begin()->at(0);
  else
    return "";
}

}

