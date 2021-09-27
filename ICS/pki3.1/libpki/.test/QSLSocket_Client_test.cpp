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
        "������ڷ� ������ ������� �Է��ؾ� �մϴ�." << endl
        << "������ ������ ip �ּ�" << endl 
        << "������ ������ ��Ʈ ��ȣ" << endl 
        << "�׽�Ʈ Ŭ���̾�Ʈ ������ ���� ���" << endl 
        << "�׽�Ʈ Ŭ���̾�Ʈ �����Ű ���� ���" << endl 
        << "�׽�Ʈ Ŭ���̾�Ʈ �����Ű PIN" << endl; 
    exit(-1);
  }
  // �������� �����Ű�� ��´�.
  cout << "Ŭ���̾�Ʈ �������� �н��ϴ�" << endl;
  boost::shared_ptr<Certificate> cert(ReadCert(argv[3]), ASN_Delete);
  if (cert.get() == NULL)
  {
    cerr << "Ŭ���̾�Ʈ ������ �б� ����" << endl;
    exit(-1);
  }
  cout << "Ŭ���̾�Ʈ �����Ű�� �н��ϴ�" << endl;
  cout << argv[4] << "," << argv[5] << endl;
  boost::shared_ptr<PrivateKeyInfo> priKey(
      ReadPriKey(argv[4], argv[5]), ASN_Delete);
  if (priKey.get() == NULL)
  {
    cerr << "Ŭ���̾�Ʈ �����Ű �б� ����" << endl;
    exit(-1);
  }
  string sendBuf = "This is a QSLSocket client test";
  string recvBuf;
  try
  {
    cout << "������ �����ϰ� �ֽ��ϴ�" << endl;
    QSLSocket qslSocket;
    qslSocket.connect(argv[1], atoi(argv[2]));
    cout << "��û ������ �����ϰ� �ֽ��ϴ�" << endl;
    qslSocket.initClientSession(cert.get(), priKey.get());
    cout << "�������� ��û �޽����� �����ϰ� �ֽ��ϴ�" << endl;
    qslSocket.sendLengthAndData(sendBuf);
    cout << "���� ���� �޽����� �����ϰ� �ֽ��ϴ�" << endl;
    qslSocket.recvLengthAndData(recvBuf);
    cout << "���� ���� �޽��� : " << recvBuf << endl;
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

PrivateKeyInfo *ReadPriKey(const char *priKeyPath, const char *passwd)
{
  PrivateKeyInfo *priKey;
  ASNBuf *asnBuf;
  asnBuf = ASNBuf_NewFromFile(priKeyPath);
  PIEX_GetPKInfoFromEPKInfoBuf(&priKey, asnBuf, passwd);
  ASNBuf_Del(asnBuf);
  return priKey;
}

