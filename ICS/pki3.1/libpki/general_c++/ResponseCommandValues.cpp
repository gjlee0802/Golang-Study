#include <sstream>

#include "ResponseCommandValues.hpp"
#include "Exception.hpp"

namespace Issac
{

#define LAB_TYPE_RESPONSE_COMMAND           "LAB_TYPE_RESPONSE_COMMAND"
#define LAB_VALUE_TAG_BASIC_OUTPUTS         "LAB_VALUE_TAG_BASIC_OUTPUTS"

using namespace std;

ResponseCommandValues::~ResponseCommandValues()
{
}

ResponseCommandValues::ResponseCommandValues(const TypedValues &vals)
{
  if (vals.getType() != getType())
    throw Exception("ResponseCommandValues: bad cast from TypedValues");
}

ResponseCommandValues::ResponseCommandValues()
{
  setType(LAB_TYPE_RESPONSE_COMMAND);
}

vector<BasicOutput> ResponseCommandValues::getBasicOutputs() const
{
  vector<BasicOutput> rets;
  const_iterator i;
  int index = 0;
  ostringstream ost;

  while (ost.str(""), ost << ++index, 
      (i = find(ost.str() + "FIRST")) != end())
  {
    BasicOutput output;
    output.first = atoi(i->second.c_str());
    if ((i = find(ost.str() + "SECOND")) != end())
      output.second = i->second;

    rets.push_back(output);
  }
  return rets;
}

void ResponseCommandValues::setBasicOutputs(const vector<BasicOutput> &outputs)
{
  string buf;
  int index = 0;
  for (vector<BasicOutput>::const_iterator i = outputs.begin();
      i != outputs.end(); ++i)
  {
    ostringstream num, ret;
    num << ++index;
    ret << i->first;
    (*this)[num.str() + "FIRST"] = ret.str();
    (*this)[num.str() + "SECOND"] = i->second;
  }
}

}

