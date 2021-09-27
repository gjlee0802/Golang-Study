#include <sstream>

#include "IDPASSWDsValues.hpp"
#include "Exception.hpp"
#include "Trace.h"

namespace Issac
{

#define LAB_TYPE_IDPASSWD     "LAB_TYPE_IDPASSWD"
#define LAB_VALUE_TAG_ID      "LAB_VALUE_TAG_ID"
#define LAB_VALUE_TAG_PASSWD  "LAB_VALUE_TAG_PASSWD"

using namespace std;

IDPASSWDsValues::~IDPASSWDsValues()
{
}

IDPASSWDsValues::IDPASSWDsValues(const TypedValues &vals)
{
  if (vals.getType() != getType())
    throw Exception("IDPASSWDsValues: bad cast from TypedValues");
}

string IDPASSWDsValues::getType() const
{
  return LAB_TYPE_IDPASSWD;
}

IDPASSWDsValues::IDPASSWDsValues()
{
  setType(LAB_TYPE_IDPASSWD);
}

void IDPASSWDsValues::getIDPASSWD(string &id, string &passwd) const
{
  ostringstream ost;
  ost << LAB_VALUE_TAG_ID << 1;

  const_iterator i;
  if ((i = find(ost.str())) == end())
    id == "";
  else
    id = i->second;

  ost.str("");
  ost << LAB_VALUE_TAG_PASSWD << 1;
  if ((i = find(ost.str())) == end())
    passwd == "";
  else
    passwd = i->second;
}

void IDPASSWDsValues::getIDPASSWDs(vector< pair<string, string> > &idpasswds) 
  const
{
  idpasswds.clear();

  int index = 0;
  const_iterator i;
  ostringstream ost;
  while (ost.str(""), ost << LAB_VALUE_TAG_ID << ++index, 
      i = find(ost.str()), i != end())
  {
    string id = i->second;

    ost.str("");
    ost << LAB_VALUE_TAG_PASSWD << index;
    i = find(ost.str());
    string passwd;
    if (i != end())
      passwd = i->second;

    idpasswds.push_back(pair<string, string>(id, passwd));
  }
}

void IDPASSWDsValues::setIDPASSWD(std::string id, std::string passwd)
{
  clear();

  ostringstream ost;
  ost << LAB_VALUE_TAG_ID << 1;
  (*this)[ost.str()] = id;

  ost.str("");
  ost << LAB_VALUE_TAG_PASSWD << 1;
  (*this)[ost.str()] = passwd;
}

void IDPASSWDsValues::setIDPASSWDs(const vector< pair<string, string> > 
    &idpasswds)
{
  clear();

  int index = 0;
  for (vector< pair<string, string> >::const_iterator i = idpasswds.begin();
      i != idpasswds.end(); ++i)
  {
    ostringstream ost;
    ost << LAB_VALUE_TAG_ID << ++index;
    (*this)[ost.str()] = i->first;
    ost.str("");
    ost << LAB_VALUE_TAG_PASSWD << index;
    (*this)[ost.str()] = i->second;
  }
}

};

