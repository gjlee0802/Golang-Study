#include <iostream>
#include <vector>
#include <boost/tokenizer.hpp>
#include <boost/shared_ptr.hpp>

// cis headers
#include "asn1.h"
#include "cert.h"
#include "piex.h"
#include "qsl.h"

#include "QSLSocket.hpp"
#include "SocketHelper.h"
#include "NetworkCommand.hpp"
#include "Trace.h"

using namespace Issac;
using namespace std;

Certificate *ReadCert(const char *certPath)
{
  return CERT_NewFromFile(certPath);
}

PrivateKeyInfo *ReadPriKey(const char *priKeyPath, const char *passwd)
{
  PrivateKeyInfo *priKey;
  ASNBuf *asnBuf;
  asnBuf = ASNBuf_NewFromFile(priKeyPath);
  PIEX_GetPKInfoFromEPKInfoBuf(&priKey, asnBuf, passwd);
  ASNBuf_Del(asnBuf);
  return priKey;
}

int main(int argc, char * const* argv)
{
  if (argc < 7)
  {
    cerr << "Usage: netcmd.exe cert.cer key.key pin ip port command ..." 
      << endl;
    exit(1);
  }
  try
  {
    cout << "클라이언트 인증서를 읽습니다" << endl;
    boost::shared_ptr<Certificate> cert(ReadCert(argv[1]), ASN_Delete);
    if (cert.get() == NULL)
    {
      cerr << "클라이언트 인증서 읽기 실패" << endl;
      exit(-1);
    }
    cout << "클라이언트 비공개키를 읽습니다" << endl;
    boost::shared_ptr<PrivateKeyInfo> priKey(
        ReadPriKey(argv[2], argv[3]), ASN_Delete);

    if (priKey.get() == NULL)
    {
      cerr << "클라이언트 비공개키 읽기 실패" << endl;
      exit(-1);
    }

    QSLSocket *sock = new QSLSocket;
    sock->connect(argv[4], atoi(argv[5]));
    cout << "컨트롤 데몬과 커넥션을 맺습니다." << endl;
    sock->initClientSession(cert.get(), priKey.get());
    NetworkCommand::setSock(sock);

    for (int i = 6; i < argc; ++i)
    {
      string c = argv[i];

      boost::escaped_list_separator<char> sep('\\', ',', '\"');
      boost::tokenizer< boost::escaped_list_separator<char> > tok(c, sep);
      vector<string> args;
      copy(tok.begin(), tok.end(), back_inserter(args));

      if (args.empty())
        continue;

      string id = args[0];
      BasicInput input;
      if (args.size() > 1)
        input.first = args[1];
      if (args.size() > 2)
        input.second = args[2];

      NetworkCommand cmd("dummy", id);

      cout << "COMMAND: " << id << endl;
      cout << "ARGS: " << input.first << endl;
      cout << "INPUT: " << input.second << endl;

      vector<BasicOutput> rets = cmd.execute(input);
      for (vector<BasicOutput>::iterator i = rets.begin(); i != rets.end();
          ++i)
      {
        cout << "return value: " << i->first << endl;
        cout << "out string: " << endl;
        cout << "'" << i->second << "'" << endl;
      }
    }
    NetworkCommand::getSock()->close();

  }
  catch (std::exception &e)
  {
    cerr << "오류발생" << endl;
    cerr << e.what() << endl;
  }
  return 0;
}

