#include <boost/scoped_array.hpp>

// cis headers
#include "ckm_pkcrypt.h"
#include "qsl.h"
#include "zip.h"
#include "x509pkc.h"

#include "Trace.h"

// QSLSocket headers
#include "QSLSocket.hpp"

namespace Issac
{

using namespace std;

QSLSocket::QSLSocket(SOCKET sock) : Socket(sock)
{
}

QSLSocket::QSLSocket(const Socket& sock) : Socket(sock)
{
}

QSLSocket::~QSLSocket()
{
}

const char *QSL_ACCEPT = "QSL_ACCEPT";
const char *QSL_REFUSE = "QSL_REFUSE";

void QSLSocket::initClientSession(
  const Certificate *cert, const PrivateKeyInfo *priKey)
{
  char senderDN[512];
  if (::Name_SprintLine(
        senderDN, sizeof(senderDN), 
        cert->tbsCertificate->subject) < 0)
    throw QSLSocketError(
        "Name_SprintLine: 인증서에서 subject를 추출할 수 없습니다.");

  char ser[512];
  if (::ASNInt_GetStr(ser, sizeof(ser), cert->tbsCertificate->serialNumber)
        < 0)
    throw QSLSocketError(
        "Name_SprintLine: 인증서에서 serialNumber를 추출할 수 없습니다.");

  Socket::sendLengthAndData(senderDN);
  Socket::sendLengthAndData(ser);
  string ret1, ret2;
  Socket::recvLengthAndData(ret1);
  Socket::recvLengthAndData(ret2);

  if (ret1 == QSL_REFUSE)
    throw QSLSocketError(
        string("서버 접속 거부: ") + ret2);

  // 1. session 생성
  _session.reset(::QSL_Server_New(const_cast<PrivateKeyInfo *>(priKey), 
        const_cast<Certificate *>(cert)), ::QSL_Del);
  if (_session.get() == NULL)
    throw QSLSocketError("Can't allocate request session");

  // 4.2. 성공인 경우
  _recvQSLHeader();

  // 5. ACK 보내기
  _sendQSLHeader();
}

void QSLSocket::initServerSession(const Certificate *cert)
{
  // 1. 암호화된 세션 정보 생성해서 client에 전송

  // 1.1. session 생성
  _session.reset(::QSL_Client_New(const_cast<Certificate *>(cert), QSL_AES), 
      ::QSL_Del);
  if (_session.get() == NULL)
    throw QSLSocketError("Can't allocate response session");

  // 1.2. 성공 메시지 생성해서 전송
  _sendQSLHeader();

  // 2. ACK 수신
  _recvQSLHeader();
}

void QSLSocket::sendLengthAndData(const std::string &buf)
{
  sendLengthAndData(buf.c_str(), buf.size());
}

void QSLSocket::sendLengthAndData(const void *buf, size_t len)
{
  // compress payload
  char *zipBuf;
  unsigned long zipLen = 0;

  int ret = ::Compression_Zip(&zipBuf, &zipLen, static_cast<char *>
      (const_cast<void *>(buf)), len);
  if (ret != SUCCESS)
    throw QSLSocketError("Fail to commpress message");

  BYTE *dataBuf = new BYTE[sizeof(BT32) + zipLen];
  ::memcpy(dataBuf + sizeof(BT32), zipBuf, zipLen);
  ::Compression_Free(&zipBuf);

  // add uncompressed len
  *reinterpret_cast<BT32 *>(dataBuf) = htonl(len);

  // encrypt body
  boost::scoped_array<BYTE> encryptedBuf(
    new BYTE[QSL_DATAHEAD_LEN + sizeof(BT32) + zipLen + 32]);
  int encryptedLen;
  ret =::QSL_DATA_Encrypt(
    encryptedBuf.get() + QSL_DATAHEAD_LEN, &encryptedLen,
    dataBuf, sizeof(BT32) + zipLen, _session.get());
  delete[] dataBuf;
  if (static_cast<unsigned int>(encryptedLen) > sizeof(BT32) + zipLen + 32)
    throw QSLSocketError("Encrypted data length is too long");
  if (ret != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to encrypt qsl data");
    else 
      throw QSLSocketError(buf);
  }

  // make datahead
  if (::QSL_DATAHEAD_Write(
    encryptedBuf.get(), true, encryptedLen) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to write qsl datahead");
    else 
      throw QSLSocketError(buf);
  }

  // Socket::send body
  Socket::send(encryptedBuf.get(), QSL_DATAHEAD_LEN + encryptedLen);
}

void QSLSocket::recvLengthAndData(string &recvBuf)
{
  // receive datahead
  BYTE dataHead[QSL_DATAHEAD_LEN];
  Socket::recv(dataHead, sizeof(dataHead));

  // resolve datahead
  int eFlag, dataLen;
  if (::QSL_DATAHEAD_Read(&eFlag, &dataLen, dataHead) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to read qsl datahead");
    else 
      throw QSLSocketError(buf);
  }
  else if (eFlag != 1) 
    throw QSLSocketError("Encryption flag is off");

  // receive body
  BYTE *data = new BYTE[dataLen];
  Socket::recv(data, dataLen);

  // decrypt body
  boost::scoped_array<BYTE> decryptedBuf(new BYTE[dataLen + 32]);
  int decryptedLen;
  int ret = ::QSL_DATA_Decrypt(
    decryptedBuf.get(), &decryptedLen, data, dataLen, _session.get());
  delete[] data;
  if (decryptedLen > dataLen + 32)
    throw QSLSocketError("Decrypted data length is too long");

  if (ret != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to decrypt qsl data decrypt failure");
    else 
      throw QSLSocketError(buf);
  }

  // get uncompressed len
  unsigned long zipLen =
    static_cast<unsigned long>(
      *reinterpret_cast<BT32 *>(decryptedBuf.get()));

  // uncompress body
  zipLen = ntohl(zipLen);
  recvBuf.resize(zipLen);
  char *tmp = const_cast<char *>(recvBuf.c_str());
  ret = ::Compression_UnZip(
    &tmp, &zipLen,
    reinterpret_cast<char *>(decryptedBuf.get() + sizeof(BT32)),
    decryptedLen - sizeof(BT32));
  if (ret != SUCCESS)
    throw QSLSocketError("Fail to uncompress message");
}

void QSLSocket::_sendQSLHeader()
{
  const int QSL_HEADER_MAX_LEN = 1024;

  BYTE header[QSL_MASTER_LEN + QSL_HEADER_MAX_LEN];

  // 1. make header
  int headerLen;
  if (::QSL_HEADER_Write(
    header + QSL_MASTER_LEN, &headerLen,
    QSL_HEADER_MAX_LEN, _session.get()) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
        ::strlen(buf) == 0)
      throw QSLSocketError("Fail to write qsl header");
    throw QSLSocketError(buf);
  }

  // 2. make master
  if (::QSL_MASTER_Write(header, QSL_VERSION, headerLen) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to write qsl master");
    throw QSLSocketError(buf);
  }

  // 3. Socket::send header
  Socket::send(header, QSL_MASTER_LEN + headerLen);

}

void QSLSocket::_recvQSLHeader()
{
  // 1. receive master header
  BYTE master[QSL_MASTER_LEN];
  Socket::recv(master, sizeof(master));

  // 2. resolve master header
  const int QSL_HEADER_MAX_LEN = 1024;
  int ver, headerLen;
  if (::QSL_MASTER_Read(&ver, &headerLen, master) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to resolve qsl master");
    throw QSLSocketError(buf);
  }
  else if (ver != QSL_VERSION) 
    throw QSLSocketError("Invalid qsl version");
  else if (headerLen > QSL_HEADER_MAX_LEN)
    throw QSLSocketError("Invalid qsl header length");

  // 3. receive header
  BYTE header[QSL_HEADER_MAX_LEN];
  Socket::recv(header, headerLen);

  // 4. resolve header
  if (::QSL_HEADER_Read(_session.get(), header, headerLen) != SUCCESS)
  {
    char buf[1024];
    if (::QSL_GetErrorMsg(buf, sizeof(buf), _session.get()) != SUCCESS ||
      ::strlen(buf) == 0)
      throw QSLSocketError("Fail to resolve qsl header");
    throw QSLSocketError(buf);
  }

}

void QSLSocket::recvRequester(string &dn, string &ser)
{
  Socket::recvLengthAndData(dn);
  Socket::recvLengthAndData(ser);
}

void QSLSocket::reply(const std::string reply, bool ok)
{
  string res = ok ? QSL_ACCEPT : QSL_REFUSE;
  Socket::sendLengthAndData(res);
  Socket::sendLengthAndData(reply);
}

} // end of namespace Issac

