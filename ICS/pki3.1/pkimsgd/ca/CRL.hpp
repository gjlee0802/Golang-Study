/**
 * @file    CRL.hpp
 *
 * @desc    CRL 갱신을 하는 class
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2002.05.15
 */

#ifndef ISSAC_CRL_HPP_
#define ISSAC_CRL_HPP_

#include "crl.h" // from cis

#include "CnK_define.hpp"
#include "LogException.hpp"

namespace Issac
{

class CRLException : public LogException
{
public:
  CRLException(int code = -1)
    : LogException(code)
  {
  }

  virtual ~CRLException() throw() {}
};

class CRLBase
{
public:
  void issue();
  bool checkIfNeedUpdate();
  virtual ~CRLBase();


protected:
  boost::shared_ptr<CRL> _crl;

  typedef struct _CRL_DBAttrName
  {
    int         crlType;
    const char *dbLastUpdate;
    const char *dbUpdatePeriod;
    const char *dbExtension;
    const char *dbCrlNumber;
    const char *fileName;
    const char *backupFileName;
    const char *dbUpdateMargin;
  } CRLBasicAttr;

  void saveToFile(CRL* crl, int crlNumber, std::string fileName = "");

  static int calcNextUpdateTime(
    struct tm *tmNextUpdate,
    struct tm tmLastUpdate,
    int basicHour,
    int basicMin,
    int updatePeriod);

  void updateDB(int crlNumber, struct tm tmThisUpdate);

  int getCRLNumber();

  virtual int getBaseCRLNumber();

  int getUpdateMargin();

  int getUpdatePeriod();

  virtual std::string getSQLStatement(std::string cdp = "") = 0;

  virtual const CRLBasicAttr getDBAttrName() = 0;

  virtual std::string name() = 0;

  void _issue(std::string cdp = "", std::string fileName = "");
};

class CRLProcess: public CRLBase
{
public:
  virtual ~CRLProcess();
  virtual std::string name();

protected:
  virtual std::string getSQLStatement(std::string cdp = "");
  virtual const CRLBasicAttr getDBAttrName();
};

class DCRLProcess : public CRLBase
{
public:
  virtual ~DCRLProcess();
  virtual std::string name();

protected:
  virtual std::string getSQLStatement(std::string cdp = "");
  virtual const CRLBasicAttr getDBAttrName();
  int getBaseCRLNumber();
};

class ARLProcess : public CRLBase
{
public:
  virtual ~ARLProcess();
  virtual std::string name();

protected:
  virtual std::string getSQLStatement(std::string cdp = "");
  virtual const CRLBasicAttr getDBAttrName();
};

}

#endif /* ISSAC_CRL_HPP_ */
