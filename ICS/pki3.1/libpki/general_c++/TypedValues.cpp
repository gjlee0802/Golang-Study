#include <stdio.h>

#include "TypedValues.hpp"
#include "Exception.hpp"

namespace Issac
{

using namespace std;

#define LAB_TYPE_TAG "LAP_TYPE_TAG"

TypedValues::~TypedValues()
{
}

std::string TypedValues::getType() const
{
  const_iterator i = find(LAB_TYPE_TAG);
  if (i == end())
    return "";
  else
    return i->second;
}

string TypedValues::getBuffer()
{
  setType(getType());
  return LabeledValues::getBuffer();
}

void TypedValues::setType(std::string type)
{
  (*this)[LAB_TYPE_TAG] = type;
}

void TypedValues::loadFromBuffer(std::string buf)
{
  LabeledValues::loadFromBuffer(buf);
  if (TypedValues::getType() != getType())
    throw Exception("TypedValues::loadFromBuffer: bad type buffer");
}

};

