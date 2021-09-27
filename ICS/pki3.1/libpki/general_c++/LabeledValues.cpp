#include <stdio.h>

#include "LabeledValues.hpp"

namespace Issac
{

using namespace std;

#define DEL "-u^$&%#@#-"

LabeledValues::~LabeledValues()
{
}

std::string LabeledValues::getBuffer()
{
  string ret;
  const_iterator i;
  for (i = begin(); i != end(); i++)
  {
    ret += DEL;
    ret += i->first + DEL + i->second;
  }
  return ret;
}

void LabeledValues::loadFromBuffer(string buf)
{
  this->clear();
  int prev = 0;
  int next;

  while ((prev = buf.find(DEL, prev)) != -1)
  {
    next = buf.find(DEL, prev + 1);
    if (next == -1)
      next = buf.size() + 1;
    string key = buf.substr(prev + strlen(DEL), 
      next - prev - strlen(DEL));
    prev = next;
    
    next = buf.find(DEL, prev + 1);
    if (next == -1)
      next = buf.size() + 1;
    string value = buf.substr(prev + strlen(DEL), 
        next - prev - strlen(DEL));
    prev = next;

    /* 키가 겹치면 첫번째 값만 들어간다. */
    insert(value_type(key, value));
  }
}

};
