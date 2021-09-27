#include <iostream>

#include "ResponseCommandValues.hpp"

using namespace Issac;
using namespace std;

int main(void)
{
  vector<BasicOutput> rets;
  rets.push_back(make_pair(1, "TEST"));
  rets.push_back(make_pair(2, "HOHOHO"));
  ResponseCommandValues v;
  v.setBasicOutputs(rets);
  vector<BasicOutput> outs = v.getBasicOutputs();

  for (vector<BasicOutput>::iterator i = outs.begin();
    i != outs.end(); ++i)
  {
    cout << i->first << endl;
    cout << i->second << endl;
  }

  return 0;
}
