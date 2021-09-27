#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <stdexcept>

#include "ProcessHandler.hpp"
#include "ProcessCommand.hpp"

using namespace Issac;
using namespace std;

#define TEST_HEADER   "\n### 테스트 단계: "
#define TEST_HEADER_1 "\n##  "
#define TEST_HEADER_2 "\n#   "

int main(int argc, char * const *argv)
{
  try
  {
    cout << "ProcessHandler test" << endl;
    string proc, args;

    if (argc > 1)
    {
      proc = argv[1];
      for (int i = 2; i < argc; ++i)
      {
        args += argv[i];
        args += " ";
      }
    }
    else
      proc = "/usr/bin/cat";

    string input = "안녕하세요\n또 만났군요";
    string output;
    int ret;

    ret = ProcessExecute(proc, args, input, output);

    cout << "excecuted '" << proc << "' with argument '" << args << 
      "' and with input stream -----" << endl <<
      input << endl << "-----" << "output -----" << endl << 
      output << endl << "-----" << endl << "returned " << "'" << ret << "'" << 
      endl;

    cout << "ProcessCommand test in same conditions" << endl;
    ProcessCommand cmd(proc);
    vector<BasicOutput> rets =  cmd.execute(BasicInput(args, input));
    for (vector<BasicOutput>::iterator i = rets.begin();i != rets.end(); i++)
    {
      cout << "result is: " << endl;
      cout << i->second << endl;
      cout << "returned '" << i->first << endl;
    }
    /*
       ProcessCommand cmd2("/cygdrive/c/WINNT/system32/net");
       rets =  cmd2.execute(BasicInput("user aaaa aaaa /ADD", ""));
       for (vector<BasicOutput>::iterator i = rets.begin();i != rets.end(); i++)
       {
       cout << "result is: " << endl;
       cout << i->second << endl;
       cout << "returned '" << i->first << endl;
       }
     */
  }
  catch (std::exception &e)
  {
    cerr << "\n## 오류가 발생하였습니다.(" << e.what() << ")" << endl;
  }

  return 0;
}

