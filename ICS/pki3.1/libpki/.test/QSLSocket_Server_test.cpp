// standard headers
#include <iostream>
#include <stdexcept>

#include <boost/shared_ptr.hpp>

// cis headers
#include "cert.h"
#include "QSLSocket.hpp"
#include "SocketHelper.h"
#include "asn1.h"

using namespace std;
using namespace boost;

using namespace Issac;

Certificate *ReadCert(const char *certPath);

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    cerr << "명령인자로 다음을 순서대로 입력해야 합니다." << endl
        << "서버가 listen할 포트 번호" << endl 
        << "테스트 클라이언트 인증서 파일 경로" << endl; 
    exit(-1);
  }
  // 클라이언트의 인증서를 얻는다.
  cout << "클라이언트 인증서를 읽습니다" << endl;
  boost::shared_ptr<Certificate> cert(ReadCert(argv[2]), ASN_Delete);
  if (cert == NULL)
  {
    cerr << "클라이언트 인증서 읽기 실패" << endl;
    exit(-1);
  }
  string sendBuf = "OK! It's all over";
  string recvBuf;
  struct    sockaddr_in addr;
  socklen_t lenSoc = sizeof(addr);
  try
  {
    Socket server;
    cout << "소켓을 listen하고 있습니다" << endl;
    server.listen(atoi(argv[1]));
    cout << "소켓을 accept하고 있습니다" << endl;
    QSLSocket qslSocket = server.accept((struct sockaddr*)&addr, &lenSoc);
    cout << "응답 세션을 생성하고 있습니다" << endl;
    string dn, ser;
    qslSocket.recvRequester(dn, ser);
    cout << "req dn is: " << dn << "," << ser << endl;
    qslSocket.reply("ok");
    qslSocket.initServerSession(cert.get());
    cout << "클라이언트 요청 메시지를 수신하고 있습니다" << endl;
    qslSocket.recvLengthAndData(recvBuf);
    cout << "클라이언트 요청 메시지 : " << recvBuf << endl;
    cout << "클라이언트에게 응답 메시지를 전송하고 있습니다" << endl;
    qslSocket.sendLengthAndData(sendBuf);
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
