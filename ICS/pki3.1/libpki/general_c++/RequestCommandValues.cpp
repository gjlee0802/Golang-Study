#include <sstream>

#include "RequestCommandValues.hpp"
#include "Exception.hpp"

namespace Issac
{

#define LAB_TYPE_REQUEST_COMMAND           "LAB_TYPE_REQUEST_COMMAND"
#define LAB_VALUE_TAG_REQUEST_ID           "LAB_VALUE_TAG_REQUEST_ID"
#define LAB_VALUE_TAG_HOST                 "LAB_VALUE_TAG_HOST"
#define LAB_VALUE_TAG_INPUT                "LAB_VALUE_TAG_INPUT"
#define LAB_VALUE_TAG_ARGS                 "LAB_VALUE_TAG_ARGS"

using namespace std;

RequestCommandValues::~RequestCommandValues()
{
}

RequestCommandValues::RequestCommandValues(const TypedValues &vals)
{
  if (vals.getType() != getType())
    throw Exception("RequestCommandValues: bad cast from TypedValues");
}

RequestCommandValues::RequestCommandValues()
{
  setType(LAB_TYPE_REQUEST_COMMAND);
}

string RequestCommandValues::getHost() const
{
  const_iterator i;
  if ((i = find(LAB_VALUE_TAG_HOST)) == end())
    return "";
  else
    return i->second;
}

void RequestCommandValues::setHost(const string &host)
{
  (*this)[LAB_VALUE_TAG_HOST] = host;
}


string RequestCommandValues::getRequestID() const
{
  const_iterator i;
  if ((i = find(LAB_VALUE_TAG_REQUEST_ID)) == end())
    return "";
  else
    return i->second;
}

void RequestCommandValues::setRequestID(const string &id)
{
  (*this)[LAB_VALUE_TAG_REQUEST_ID] = id;
}

void RequestCommandValues::getInput(string &args, string &input) const
{
  const_iterator i;
  if ((i = find(LAB_VALUE_TAG_ARGS)) != end())
    args = i->second;
  if ((i = find(LAB_VALUE_TAG_INPUT)) != end())
    input = i->second;
}

void RequestCommandValues::setInput(const string &args, const string &input)
{
  (*this)[LAB_VALUE_TAG_ARGS] = args;
  (*this)[LAB_VALUE_TAG_INPUT] = input;
}

};

