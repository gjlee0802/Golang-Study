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
    cerr << "������ڷ� ������ ������� �Է��ؾ� �մϴ�." << endl
        << "������ listen�� ��Ʈ ��ȣ" << endl 
        << "�׽�Ʈ Ŭ���̾�Ʈ ������ ���� ���" << endl; 
    exit(-1);
  }
  // Ŭ���̾�Ʈ�� �������� ��´�.
  cout << "Ŭ���̾�Ʈ �������� �н��ϴ�" << endl;
  boost::shared_ptr<Certificate> cert(ReadCert(argv[2]), ASN_Delete);
  if (cert == NULL)
  {
    cerr << "Ŭ���̾�Ʈ ������ �б� ����" << endl;
    exit(-1);
  }
  string sendBuf = "OK! It's all over";
  string recvBuf;
  struct    sockaddr_in addr;
  socklen_t lenSoc = sizeof(addr);
  try
  {
    Socket server;
    cout << "������ listen�ϰ� �ֽ��ϴ�" << endl;
    server.listen(atoi(argv[1]));
    cout << "������ accept�ϰ� �ֽ��ϴ�" << endl;
    QSLSocket qslSocket = server.accept((struct sockaddr*)&addr, &lenSoc);
    cout << "���� ������ �����ϰ� �ֽ��ϴ�" << endl;
    string dn, ser;
    qslSocket.recvRequester(dn, ser);
    cout << "req dn is: " << dn << "," << ser << endl;
    qslSocket.reply("ok");
    qslSocket.initServerSession(cert.get());
    cout << "Ŭ���̾�Ʈ ��û �޽����� �����ϰ� �ֽ��ϴ�" << endl;
    qslSocket.recvLengthAndData(recvBuf);
    cout << "Ŭ���̾�Ʈ ��û �޽��� : " << recvBuf << endl;
    cout << "Ŭ���̾�Ʈ���� ���� �޽����� �����ϰ� �ֽ��ϴ�" << endl;
    qslSocket.sendLengthAndData(sendBuf);
    cout << "��� �׽�Ʈ�� ���������� ���ƽ��ϴ�" << endl;
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
