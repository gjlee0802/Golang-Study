
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <string>

#include "GetProfile.h"
#include "GetProfileEx.hpp"
#include "er_define.h"

using namespace std;

void GetProfileEx(const std::string &filePath, const std::string &section, 
                  const std::string &key, std::string &value, 
                  const std::string &defVal)
{
  //char line[MAX_BUFFER_SIZE], *token;
  string sec, line;

  sec = "[";
  sec += section + "]";

  value = defVal;

  ifstream file(filePath.c_str());
  if (!file)
  {
    return;
  }

  while (getline(file, line))
  {
    if (line == sec)
    {
      while (getline(file, line))
      {
        string::size_type pos;
        if (line[0] == '[')
          return;
        if ((pos = line.find("=")) != string::npos)
        {
          string att = line.substr(0, pos);
          if (att == key)
          {
            if (line.size() <= att.size() + 1)
            {
              value = "";
              return;
            }
            value = line.substr(pos + 1, line.size() - pos - 1);
            return;
          }
        }
      }
      return;
    }
  }
  return;
}

void SetProfileEx(const std::string &filePath, const std::string &section, 
    const std::string &key, const std::string &value)
{
  SetProfile(filePath.c_str(), section.c_str(), key.c_str(), value.c_str());
}

void DeleteProfileEx(const std::string &filePath, const std::string &section, 
    const std::string &key)
{
  DeleteProfile(filePath.c_str(), section.c_str(), key.c_str());
}

