#include <iostream>

#include "LabeledValues.hpp"
#include "TypedValues.hpp"

using namespace Issac;
using namespace std;

int main(void)
{
  TypedValues vals;
  vals["key1"] = "val1";
  vals["key2"] = "val2";

  cout << vals["key1"] << ", " << vals["key2"] << endl;
  
  string buf = vals.getBuffer();
  vals.loadFromBuffer(buf);
  cout << vals["key1"] << ", " << vals["key2"] << endl;

  return 0;
}
