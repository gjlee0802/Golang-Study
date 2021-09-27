/**
 * @file    CRL.cpp
 *
 * @desc    CRL 갱신을 하는 클래스
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2003.09.15
 *
 * Revision history
 *
 * @date    2002.05.15 : Start
 */

// standard headers
#include <errno.h>
#include <cassert>
#include <string>
#include <sstream>
#include <ctime>
#include <boost/shared_ptr.hpp>

// cis headers
#include "crl.h"

// pkisys headers
#include "dbi.h"

#include "DBObject.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"
#include "CRLHelper.h"
#include "Exception.hpp"
#include "cis_cast.hpp"
#include "Trace.h"

#include "CALoginProfile.hpp"
#include "PKILogTableDefine.hpp"

#include "CRL.hpp"
#include "CMP.hpp"

#define TMPLOG "/tmp/msgd.log"

using namespace std;
using namespace Issac::DB;

namespace Issac
{

///////////////////////////////////////////////////
//
//  CRLBase class

CRLBase::~CRLBase()
{
}

int CRLBase::getBaseCRLNumber()
{
  return 0;
}

void CRLBase::saveToFile(CRL *crl, int crlNumber, string fileName)
{
  boost::shared_ptr<ASNBuf> crlBuf(ASN_EncodeDER(crl), ASNBuf_Delete);

  // 1. Main CRL 저장
  if (fileName.empty())
    fileName = CALoginProfile::get()->getCrlDir() + getDBAttrName().fileName;

  if (SUCCESS !=
    ::ASNBuf_SaveToFile(crlBuf.get(), fileName.c_str()))
  {
    /*# ERROR : Fail to save CRL */
    /*# LOG : CRL 저장 실패 */
    CRLException e(LOG_CAMSGD_FAIL_TO_SAVE_CRL_N);
    e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)",
        getDBAttrName().crlType);
    throw e;
  }

  /*
  // 2. Backup CRL 저장
  char buf[32];
  sprintf(buf, getDBAttrName().backupFileName, crlNumber);
  fileName = CALoginProfile::get()->getCrlDir() + buf;
  ::ASNBuf_SaveToFile(crlBuf.get(), fileName.c_str());
  */

  /*# LOG : CRL 갱신 */
  LogItemSharedPtr logItem(LoginProfile::get()->getLog()->createLogItem());
  logItem->setLogItem(
    LOG_CAMSGD_CRL_UPDATED_N,
    "CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL) : %i, CRL Number:%i, fileName: %s",
    getDBAttrName().crlType, crlNumber, fileName.c_str());
  logItem->write();
}

/**
 * CRL 혹은 CTL의 다음 갱신 시간을 구한다.
 */
int CRLBase::calcNextUpdateTime(
  struct tm *ptrTmNextUpdate,
  struct tm tmLastUpdate,
  int basicHour,
  int basicMin,
  int updatePeriod)
{
  ER_RET_IF(ptrTmNextUpdate == NULL);
  ER_RET_IF(basicHour < 0 || basicMin  < 0 || updatePeriod < 0);

  // 갱신 기준 시각 + N * (갱신 주기) 중 (기존 갱신 시간 + 갱신 주기)보다
  // 작으면서 가장 큰 값을 얻음
  time_t timeNextUpdate = ::mktime(&tmLastUpdate);
  if (timeNextUpdate == -1) return FAIL;
  timeNextUpdate += updatePeriod * 3600;
  struct tm tmNextUpdate;
  tmNextUpdate = *::localtime(&timeNextUpdate);

  struct tm tmBasicUpdate;
  if (basicHour < tmNextUpdate.tm_hour)
  {
    tmBasicUpdate = tmNextUpdate;
    tmBasicUpdate.tm_hour = basicHour;
    tmBasicUpdate.tm_min  = basicMin;
    tmBasicUpdate.tm_sec  = 0;
  }
  else if (basicHour == tmNextUpdate.tm_hour)
  {
    if (basicMin < tmNextUpdate.tm_min)
    {
      tmBasicUpdate = tmNextUpdate;
      tmBasicUpdate.tm_min = basicMin;
      tmBasicUpdate.tm_sec  = 0;
    }
    else if (basicMin == tmNextUpdate.tm_min)
    {
      tmBasicUpdate = tmNextUpdate;
      tmBasicUpdate.tm_sec  = 0;
    }
    else
    {
      tmBasicUpdate = tmNextUpdate;
      tmBasicUpdate.tm_mday -= 1;
      tmBasicUpdate.tm_min  = basicMin;
      tmBasicUpdate.tm_sec  = 0;
    }
  }
  else
  {
    tmBasicUpdate = tmNextUpdate;
    tmBasicUpdate.tm_mday -= 1;
    tmBasicUpdate.tm_hour = basicHour;
    tmBasicUpdate.tm_min  = basicMin;
    tmBasicUpdate.tm_sec  = 0;
  }

  time_t timeBasicUpdate = ::mktime(&tmBasicUpdate);

  while (timeBasicUpdate + updatePeriod * 3600 <= timeNextUpdate)
    timeBasicUpdate += updatePeriod * 3600;

  *ptrTmNextUpdate = *::localtime(&timeBasicUpdate);

  return SUCCESS;
}

bool CRLBase::checkIfNeedUpdate()
{
  try
  {
    // 관리도구에서 강제 설정을 한 경우
    if (CALoginProfile::get()->getDP()->get(
        PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_UPDATE_REQUIRED) == "1")
      return true;

    // 1. CRL을 갱신해야 되는지 확인
    string basicTime;
    int basicHour = 0, basicMin = 0;
    try
    {
      basicTime = CALoginProfile::get()->getDP()->get(
        PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_CRL_BASIC_TIME);
    }
    catch (...) {}

    if (!basicTime.empty())
      ::sscanf(basicTime.c_str(), "%d:%d", &basicHour, &basicMin);

    int updatePeriod;
    try
    {
      updatePeriod = atoi(CALoginProfile::get()->getDP()->get(
        PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbUpdatePeriod).c_str());
    }
    catch (...)
    {
      TRACE_LOG(TMPLOG, "'%s', '%s'",
          getDBAttrName().dbUpdatePeriod,
          PKIDB_GLOBAL_CRL_SECTION);
      /*# ERROR : No crl update period value */
      /*# LOG : CRL 갱신 주기 값이 지정되어 있지 않음 */
      CRLException e(LOG_CAMSGD_FAIL_TO_FIND_CRL_UPDATEPERIOD_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
      throw e;
      // Complete CRL 이외의 경우에는 DB값이 없으면 CRL 생성하지 않음
    }

    if (updatePeriod == 0)
    {
      TRACE_LOG(TMPLOG, "'%s', '%s'",
          getDBAttrName().dbUpdatePeriod,
          PKIDB_GLOBAL_CRL_SECTION);
      /*# ERROR : No crl update period value */
      /*# LOG : CRL 갱신 주기 값이 지정되어 있지 않음 */
      CRLException e(LOG_CAMSGD_FAIL_TO_FIND_CRL_UPDATEPERIOD_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
      throw e;
      // Complete CRL 이외의 경우에는 DB값이 없으면 CRL 생성하지 않음
    }

    struct tm tmLastUpdate;
    try
    {
      tmLastUpdate = string2type<struct tm>(
        CALoginProfile::get()->getDP()->get(
        PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbLastUpdate)
        );
    }
    catch (...)
    {
      time_t t = 0;
      tmLastUpdate = *::localtime(&t);
    }

    struct tm tmNextUpdate;
    if (SUCCESS !=
      calcNextUpdateTime(
      &tmNextUpdate, tmLastUpdate, basicHour, basicMin, updatePeriod)
      )
    {
      /*# ERROR : Fail to calculate next update time */
      /*# LOG : 갱신 시각 계산 실패 */
      CRLException e(LOG_CAMSGD_FAIL_TO_CALC_NEXTUPDATE_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
      throw e;
    }

    // 아직 Next update 시간을 지나지 않았음.
    if (time(NULL) < ::mktime(&tmNextUpdate)) return false;

    return true;
  }
  catch (LogException &e)
  {
    // Log 기록
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->createLogItem());
    logItem->setLogItem(e.getCode(), e.getOpts().c_str());
    logItem->write();
  }
  return false;
}

int CRLBase::getCRLNumber()
{
  try
  {
    int crlNumber = atoi(
      CALoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbCrlNumber).c_str()
      );
    crlNumber++;
    return crlNumber;
  }
  catch (...) {}

  return 0;
}

int CRLBase::getUpdatePeriod()
{
  try
  {
    return atoi(
      CALoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbUpdatePeriod).c_str()
      );
  }
  catch (...)
  {
    // DB 에 CRL 설정 값들을 찾을 수 없음
    /*# LOG : CRL 생성 실패(CRL 설정값 가져오기 실패) */
    CRLException e(LOG_CAMSGD_FAIL_TO_GET_CRL_SETTINGS_N);
    e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
    throw e;
  }
}

int CRLBase::getUpdateMargin()
{
  const int CRL_UPDATE_MARGIN_HOUR = 1;
  int updateMargin = CRL_UPDATE_MARGIN_HOUR;
  try
  {
    updateMargin = atoi(
      CALoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbUpdateMargin).c_str()
      );
  }
  catch (...) {} // ignore

  if (!updateMargin)
  {
    if (getDBAttrName().crlType == 1)
      updateMargin = 0;
    else
      updateMargin = 1;
  }

  return updateMargin;
}

void CRLBase::issue() // touch _crlNumber
{
  try
  {
    if (CMP::isPCRL() && getDBAttrName().crlType == 0)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      int count = CMP::getPCRL_CurrentCertsCount() /
        CMP::getPCRL_UnitCerts() + 1;
      for (int i = 0; i < count; ++i)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        string fmt = LoginProfile::get()->getProfile("CRL",
            "CDP_URI_FORMAT");

        char uri[2048];
        if (!fmt.empty())
          sprintf(uri, fmt.c_str(), i);
        else
          throw Exception(
              "설정파일의 [CRL] 섹션에서 CDP_URI_FORMAT를 얻을 수 없습니다.");
        TRACE_LOG(TMPLOG, uri);
        char fileName[512];
        fmt = LoginProfile::get()->getProfile("CRL", "FILE_FORMAT");
        if (!fmt.empty())
        {
          fmt = LoginProfile::get()->getCrlDir() + fmt;
          sprintf(fileName, fmt.c_str(), i);
        }
        else
          throw Exception(
              "설정파일의 [CRL] 섹션에서 FILE_FORMAT를 얻을 수 없습니다.");
        TRACE_LOG(TMPLOG, fileName);

        _issue(uri, fileName);
      }
    }
    // 기타의 경우와 cdp가 인증서에 대한 CRL 발행
    _issue();
  }
  catch (LogException &e)
  {
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->createLogItem());
    logItem->setLogItem(e.getCode(), e.getOpts().c_str());
    logItem->write();
    throw e;
  }
}

void CRLBase::_issue(string cdp, string fileName) // touch _crlNumber
{
  CALoginProfile::get()->getDP()->set(
      PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_UPDATE_REQUIRED, "0");

  // 1. 초기화
  time_t timeNow = ::time(NULL);
  CnKSharedPtr caCnK(CALoginProfile::get()->getMyCnK());

  int crlNumber = getCRLNumber();
  int updatePeriod = getUpdatePeriod();
  int updateMargin = getUpdateMargin();

  // 1. CRL 생성
  boost::shared_ptr<CRL> crl(ASN_New(CRL, NULL), ASN_Delete);

  boost::shared_ptr<Extensions> crlExtsTemplate;
  try
  {
    crlExtsTemplate.reset(
        string2type<Extensions *>(
          CALoginProfile::get()->getDP()->get(
          PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbExtension)
        ),
        ASN_Delete);
  }
  catch (...)
  {
    // 잘못된 CRL 확장 영역 Template
    /*# LOG : 잘못된 CRL 확장 영역 Template */
    CRLException e(LOG_CAMSGD_INVALID_CRL_EXTENSION_N);
    e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
    throw e;
  }

  boost::shared_ptr<Extensions> entryExtsTemplate;
  try
  {
    entryExtsTemplate.reset(
      string2type<Extensions *>(
        CALoginProfile::get()->getDP()->get(
        PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_CRL_ENTRY_EXTENSION)
      ),
      ASN_Delete);
  }
  catch (...)
  {
    // Entry Extension은 없으면 추가하지 않음
  }

  TRACE_LOG(TMPLOG, "Extensions 설정");
  // 2.2. Extensions 설정
  boost::shared_ptr<Extensions> crlExtensions(
    ASN_New(Extensions, NULL), ASN_Delete);
  int i;
  int baseCRLNumber = getBaseCRLNumber();
  for (i = 0; i < crlExtsTemplate->size; ++i)
  {
    if (::CRL_AddExtensions(
      crlExtensions.get(), crlNumber, caCnK.first.get(), baseCRLNumber,
      crlExtsTemplate->member[i]) != SUCCESS)
    {
      // CRL 확장 영역 추가 실패
      /*# LOG : CRL 생성 실패(CRL 확장 영역 추가 실패) */
      CRLException e(LOG_CAMSGD_FAIL_TO_ADD_CRLEXTENSION_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
      throw e;
    }
  }

  TRACE_LOG(TMPLOG, "TBSCertList 설정");
  // 2.3. TBSCertList 설정
  struct tm tmThisUpdate;
  tmThisUpdate = *::gmtime(&timeNow);
  struct tm tmNextUpdate = tmThisUpdate;
  tmNextUpdate.tm_hour += updatePeriod + updateMargin;
    // CRL 갱신에 걸리는 시간을 고려한 여유 시간
  ::mktime(&tmNextUpdate);

  VERIFY(::TBSCertList_Set(
    crl->tbsCertList,
    caCnK.first->tbsCertificate->subject,
    &tmThisUpdate,
    &tmNextUpdate,
    NULL,
    crlExtensions.get()) == SUCCESS);


  // 2. CRL 필드 설정
  //  - CRL :
  //    TBSCertList         *tbsCertList;
  //    AlgorithmIdentifier *signatureAlgorithm;
  //    BitString           *signatureValue;
  //  - TBSCertList
  //    Version             *version;       /* optional */
  //    AlgorithmIdentifier *signature;
  //    Name                *issuer;
  //    Time                *thisUpdate;
  //    Time                *nextUpdate;    /* optional */
  //    RevokedCertificates *revokedCertificates;
  //    Extensions          *crlExtensions; /* optional [0] */

  // 2.1. RevokedCertificates 설정
  string sql = getSQLStatement(cdp);

  PKIDBSel *sel = ::DBI_Select(
    DBConnection::getConn(), sql.c_str());
  if (sel == NULL || ::DBI_ResultGetNumRows(sel) <= 0)
  {
    if (sel != NULL) VERIFY(::DBI_ResultFree(sel) == SUCCESS);
    sel = NULL;
  }

  while (sel != NULL)
  {
    // 2.1.1. 각각의 폐지된 인증서에 대해 RevokedCertificate 생성
    char serialNum[320];
    if (::DBI_ResultGetStrByName(serialNum, "SER", sel) < 0)
    {
      VERIFY(::DBI_ResultFree(sel) == SUCCESS);
      /*# LOG : CRL 생성 실패 */
      CRLException e(LOG_CAMSGD_FAIL_TO_MAKE_CRL_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)",
          getDBAttrName().crlType);
      throw e;
    }

    int rcode = ::DBI_ResultGetIntByName("RCODE", sel);
    time_t timeRdate, timeIdate;
    VERIFY(::DBI_ResultGetTimeByName(&timeRdate, "RDATE", sel) == SUCCESS);
    VERIFY(::DBI_ResultGetTimeByName(&timeIdate, "IDATE", sel) == SUCCESS);

    CertificateSerialNumber *certSerialNumber =
      ASN_New(CertificateSerialNumber, NULL);
    VERIFY(::ASNInt_SetStr(certSerialNumber, serialNum) != FAIL);

    RevokedCertificate *revokedCert = ::CRL_NewRevokedCertificate(
      certSerialNumber,
      timeRdate, rcode, timeIdate,
      caCnK.first->tbsCertificate->subject,
      entryExtsTemplate.get());
    ASN_Del(certSerialNumber);

    if (revokedCert == NULL)
    {
      // CRL에 Entry 추가 실패
      ::DBI_ResultFree(sel);
      /*# LOG : CRL 생성 실패(CRL Entry 추가 실패) */
      CRLException e(LOG_CAMSGD_FAIL_TO_ADD_CRLENTRY_N);
      e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
      throw e;
    }

    VERIFY(TBSCertList_AddRevocatedCert(crl->tbsCertList, revokedCert) ==
        SUCCESS);

    ASN_Del(revokedCert);

    if (::DBI_ResultNext(sel) < 0) sel = NULL;
  }

  TRACE_LOG(TMPLOG, "CRL 생성(서명)");
  // 3. CRL 서명
  int ret = ::CRL_Gen(
    crl.get(),
    crl->tbsCertList,
    caCnK.second.get(),
    NULL, /* domain parameter는 인증서 혹은 비공개키에 포함되어 있어야 함 */
    AlgNid_GetHashAlgDesc(NID_SHA1), /*# NOTE: hash algorithm은 SHA1으로 고정 */
    caCnK.first.get());

  if (ret != SUCCESS)
  {
    TRACE_LOG(TMPLOG, "CRL_Gen 오류: errno: %d", errno);
    // CRL의 서명값 생성 실패
    /*# LOG : CRL 서명값 생성 실패 */
    CRLException e(LOG_CAMSGD_FAIL_TO_SIGN_CRL_N);
    e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
    throw e;
  }
  TRACE_LOG(TMPLOG, "saveToFile");
  saveToFile(crl.get(), crlNumber, fileName);

  TRACE_LOG(TMPLOG, "updateDB");
  updateDB(crlNumber, tmThisUpdate);
}

void CRLBase::updateDB(int crlNumber, struct tm tmThisUpdate)
{
  //    CRL Number 갱신
  //    Last update 시간 변경
  try
  {
    std::ostringstream ost;
    ost << crlNumber;

    CALoginProfile::get()->getDP()->set(
      PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbCrlNumber,
      ost.str());

    ::GmtimeToLocaltime(&tmThisUpdate, &tmThisUpdate);
    CALoginProfile::get()->getDP()->set(
      PKIDB_GLOBAL_CRL_SECTION, getDBAttrName().dbLastUpdate,
      type2string<struct tm>(tmThisUpdate));
  }
  catch (...)
  {
    // DB 값 갱신 실패
    /*# LOG : CRL 생성 실패(DB 값 갱신 실패) */
    CRLException e(LOG_CAMSGD_FAIL_TO_UPDATE_DB_CRL_N);
    e.addOpt("CRL 종류(0:Complete, 1:DeltaCRL, 2:ARL)", getDBAttrName().crlType);
    throw e;
  }
}

const CRLBase::CRLBasicAttr CRLProcess::getDBAttrName()
{
  CRLBasicAttr attrName =
    { 0,
      PKIDB_GLOBAL_CRL_CRL_LAST_UPDATE, PKIDB_GLOBAL_CRL_CRL_UPDATE_PERIOD,
      PKIDB_GLOBAL_CRL_CRL_EXTENSION, PKIDB_GLOBAL_CRL_CRL_NUMBER,
      "crl.crl", "crl%08X.crl",
      "CRL Update Margin" };

  return attrName;
}

///////////////////////////////////////////////////
//
//  CRL class

string CRLProcess::name()
{
  return "CRL";
}

string CRLProcess::getSQLStatement(std::string cdp)
{
  string whereCDP;
  if (cdp.empty())
    whereCDP = " AND CDP IS NULL ";
  else
  {
    whereCDP = " AND CDP = '";
    whereCDP += cdp;
    whereCDP += "'";
  }

  std::ostringstream ost;
  ost <<
    "(SELECT SER, RDATE, RCODE, IDATE FROM PKIENTITYPKC "
    " WHERE STAT='" << PKIDB_PKC_STAT_REVOKED << "'";
  ost << whereCDP << ") ";
  ost << "UNION " "(SELECT SER, RDATE, RCODE, IDATE FROM PKIAUTHORITYPKC "
    " WHERE STAT='" << PKIDB_PKC_STAT_REVOKED << "')";

  TRACE_LOG(TMPLOG, ost.str().c_str());

  return ost.str();
}

CRLProcess::~CRLProcess()
{
}

///////////////////////////////////////////////////
//
//  DCRL class
string DCRLProcess::name()
{
  return "Delta CRL";
}

const CRLBase::CRLBasicAttr DCRLProcess::getDBAttrName()
{
  CRLBasicAttr attrName =
    { 1,
      PKIDB_GLOBAL_CRL_DCRL_LAST_UPDATE, PKIDB_GLOBAL_CRL_DCRL_UPDATE_PERIOD,
      PKIDB_GLOBAL_CRL_DCRL_EXTENSION, PKIDB_GLOBAL_CRL_DCRL_NUMBER,
      "dcrl.crl", "dcrl%08X.crl",
      "DCRL Update Margin" };

  return attrName;
}

/*# FIXME : 다음 사항이 아직 고려되어 있지 않음
    1. CRL에서 기한이 만료된 인증서를 제거하는 건 언제인가?
    2. 정지 기능 사용시 Delta CRL에서의 처리
    3. SQL문이 오라클 이외에서도 적용 가능한가? */
string DCRLProcess::getSQLStatement(std::string cdp)
{
  // DCRL 발급을 위한 Base CRL 정보를 가져온다
  struct tm tmBaseCRLLastUpdate;

  try
  {
    tmBaseCRLLastUpdate = string2type<struct tm>(
      CALoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_CRL_LAST_UPDATE)
      );
  }
  catch (...)
  {
    // DeltaCRL 발급을 하려고 하나 DB에 CompleteCRL 정보가 들어있지 않음
    /*# LOG : CRL 생성 실패(Complete CRL 정보가 없음) */
    throw CRLException(LOG_CAMSGD_FAIL_TO_GET_BASECRL_INFO_N);
  }

  std::ostringstream ost;
  ost <<
    "(SELECT SER, RDATE, RCODE, IDATE FROM PKIENTITYPKC "
    " WHERE STAT='" << PKIDB_PKC_STAT_REVOKED << "' "
    "       AND RDATE > TO_DATE('" <<
    type2string<struct tm>(tmBaseCRLLastUpdate) <<
    "         ', '" << DEFAULT_TIME_FORMAT << "')) "
    "UNION "
    "(SELECT SER, RDATE, RCODE, IDATE FROM PKIAUTHORITYPKC "
    " WHERE STAT='" << PKIDB_PKC_STAT_REVOKED << "' "
    "       AND RDATE > TO_DATE('" <<
              type2string<struct tm>(tmBaseCRLLastUpdate) <<
    "         ', '" << DEFAULT_TIME_FORMAT << "'))";

  return ost.str();
}

int DCRLProcess::getBaseCRLNumber()
{
  try
  {
    return atoi(
      CALoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CRL_SECTION, PKIDB_GLOBAL_CRL_CRL_NUMBER).c_str()
      );
  }
  catch (...)
  {
    // DeltaCRL 발급을 하려고 하나 DB에 CompleteCRL 정보가 들어있지 않음
    /*# LOG : CRL 생성 실패(Complete CRL 정보가 없음) */
    throw CRLException(LOG_CAMSGD_FAIL_TO_GET_BASECRL_INFO_N);
  }
}

DCRLProcess::~DCRLProcess()
{
}

///////////////////////////////////////////////////
//
//  ARL class
string ARLProcess::name()
{
  return "ARL";
}

const CRLBase::CRLBasicAttr ARLProcess::getDBAttrName()
{
  CRLBasicAttr attrName =
    { 2,
      PKIDB_GLOBAL_CRL_ARL_LAST_UPDATE, PKIDB_GLOBAL_CRL_ARL_UPDATE_PERIOD,
      PKIDB_GLOBAL_CRL_ARL_EXTENSION, PKIDB_GLOBAL_CRL_ARL_NUMBER,
      "arl.crl", "arl%08X.crl",
      "ARL Update Margin" };

  return attrName;
}

string ARLProcess::getSQLStatement(std::string cdp)
{
  std::ostringstream ost;
  ost <<
      "SELECT SER, RDATE, RCODE, IDATE FROM PKIAUTHORITYPKC "
      "WHERE STAT='" << PKIDB_PKC_STAT_REVOKED << "'";

  return ost.str();
}

ARLProcess::~ARLProcess()
{
}

}

