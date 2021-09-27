#include <iostream>
#include <stdexcept>

#include "SocketHelper.h"
#include "Socket.hpp"
#include "Trace.h"

using namespace std;
using namespace Issac;

#define INADDR_NONE     0xffffffff

int main()
{
  try
  {
    sockaddr_in serv_addr;
    unsigned long inaddr;
    char *ipAddress = "seafarer.pentasecurity.com";

    /* Initialize the 'struct sockaddr_in' */
    memset ((char*) &serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;

    /* Set the ip address to the 'struct sockaddr_in' */
    if ((inaddr = inet_addr (ipAddress)) != INADDR_NONE)
    {
      TRACE(PRETTY_TRACE_STRING);
      memcpy ((char *) &serv_addr.sin_addr, (char *) &inaddr, sizeof (inaddr));
    }
    else
    {
      TRACE(PRETTY_TRACE_STRING);
      struct hostent  *hent;
      if ((hent = gethostbyname(ipAddress)) == NULL)
        return -1;
      memcpy (&serv_addr.sin_addr, hent->h_addr, hent->h_length);
    }
    cout << "ok" << endl;

    TRACE("TEST_START");
    string host = "oz.pentasecurity.com";

    Socket s;
    s.connect(host, 30999);
    Socket t = s;
    cout << t.handle() << endl;

    char ip[256];
    GetIpFromHost(ip, host.c_str());
    cout << ip << endl;
    char myname[256];
    gethostname(myname, 256);
    GetIpFromHost(myname, myname);
    cout << "my ip is: " << myname << endl;
    GetIpFromHost(ip, "oz.pentasecurity.com");
    cout << "oz ip is: " << ip << endl;

  }
  catch (exception &e)
  {
    cerr << e.what() << endl;
  }

  return 0;
}
  
  
