// standard headers
#include <iostream>
#include <stdexcept>
#include <boost/shared_ptr.hpp>

// cis headers
#include "asn1.h"
#include "cert.h"
#include "piex.h"
#include "qsl.h"
#include "QSLSocket.hpp"
#include "SocketHelper.h"

using namespace std;
using namespace boost;

using namespace Issac;

Certificate *ReadCert(const char *certPath);
PrivateKeyInfo *ReadPriKey(const char *priKeyPath, const char *passwd);

int main(int argc, char **argv)
{
  if (argc != 6)
  {
    cerr << 
        "명령인자로 다음을 순서대로 입력해야 합니다." << endl
        << "접속할 서버의 ip 주소" << endl 
        << "접속할 서버의 포트 번호" << endl 
        << "테스트 클라이언트 인증서 파일 경로" << endl 
        << "테스트 클라이언트 비공개키 파일 경로" << endl 
        << "테스트 클라이언트 비공개키 PIN" << endl; 
    exit(-1);
  }
  // 인증서와 비공개키를 얻는다.
  cout << "클라이언트 인증서를 읽습니다" << endl;
  boost::shared_ptr<Certificate> cert(ReadCert(argv[3]), ASN_Delete);
  if (cert.get() == NULL)
  {
    cerr << "클라이언트 인증서 읽기 실패" << endl;
    exit(-1);
  }
  cout << "클라이언트 비공개키를 읽습니다" << endl;
  cout << argv[4] << "," << argv[5] << endl;
  boost::shared_ptr<PrivateKeyInfo> priKey(
      ReadPriKey(argv[4], argv[5]), ASN_Delete);
  if (priKey.get() == NULL)
  {
    cerr << "클라이언트 비공개키 읽기 실패" << endl;
    exit(-1);
  }
  string sendBuf = "This is a QSLSocket client test";
  string recvBuf;
  try
  {
    cout << "서버에 접속하고 있습니다" << endl;
    QSLSocket qslSocket;
    qslSocket.connect(argv[1], atoi(argv[2]));
    cout << "요청 세션을 생성하고 있습니다" << endl;
    qslSocket.initClientSession(cert.get(), priKey.get());
    cout << "서버에게 요청 메시지를 전송하고 있습니다" << endl;
    qslSocket.sendLengthAndData(sendBuf);
    cout << "서버 응답 메시지를 수신하고 있습니다" << endl;
    qslSocket.recvLengthAndData(recvBuf);
    cout << "서버 응답 메시지 : " << recvBuf << endl;
    cout << "모든 테스트를 성공적으로 마쳤습니다" << endl;
  }
  catch (QSLSocketError &e)
  {
    // error printing
    cerr << e.what() << endl;
  }
  catch (exception &e)
  {
    // error printing
    cerr << e.what() << endl;
    exit(1);
  }
  return 0;
}

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

