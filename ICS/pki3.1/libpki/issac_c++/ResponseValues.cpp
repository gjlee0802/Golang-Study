#include <sstream>

#include "ResponseValues.hpp"
#include "Exception.hpp"

namespace Issac
{

#define LAB_TYPE_RESPONSE           "LAB_TYPE_RESPONSE"
#define LAB_VALUE_TAG_RESPONSE      "LAB_VALUE_TAG_RESPONSE"

using namespace std;

ResponseValues::~ResponseValues()
{
}

ResponseValues::ResponseValues(const TypedValues &vals)
{
  if (vals.getType() != getType())
    throw Exception("ResponseValues: bad cast from TypedValues");
}

ResponseValues::ResponseValues()
{
  setType(LAB_TYPE_RESPONSE);
}

string ResponseValues::getResponse() const
{
  const_iterator i;
  if ((i = find(LAB_VALUE_TAG_RESPONSE)) == end())
    return "";
  else
    return i->second;
}

void ResponseValues::setResponse(const string &res)
{
  (*this)[LAB_VALUE_TAG_RESPONSE] = res;
}

std::string ResponseValues::getType() const
{
  return LAB_TYPE_RESPONSE;
}

};

