/**
 * @file     CMPErrorMsgTable.cpp
 *
 * @desc     PKI 에러 메시지 리스트
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2002.06.11
 *
 */

#include "cmp.h"

#include "Trace.h"

#include "CMPErrorMsgTable.hpp"
#include "PKILogTableDefine.hpp"

namespace Issac
{

//////////////////////////////////////////////////////////////////
//
//  CMPErrorMsgTable class

CMPErrorMsgTable *CMPErrorMsgTable::_inst = NULL;

CMPErrorMsgTable::CMPErrorMsgTable()
{
}

// destuctor is called twice, first for global object
// second for _inst.
CMPErrorMsgTable::~CMPErrorMsgTable()
{
}

void CMPErrorMsgTable::_init()
{
  static CMPErrorMsgTable table;
  _inst = &table;

  #include "CMPErrorMsgItems.inc" // defines cmpErrorMsgItems

  int i = 0;
  while (cmpErrMsgItems[i++].logCode)
  {
    _inst->insert(value_type(cmpErrMsgItems[i].logCode, cmpErrMsgItems[i]));
  }
}

const CMPErrorMsgTable* CMPErrorMsgTable::get()
{
  if (!_inst)
    _init();
  return _inst;
}

CMP_ERROR_MSG_TABLE_ITEM CMPErrorMsgTable::getItem(int code) const
{
  const_iterator i = _inst->find(code);
  if (i == _inst->end())
  {
    CMP_ERROR_MSG_TABLE_ITEM item;
    item.logCode = item.failInfo = item.errorCode = LOG_TABLE_INVALID_CODE;
    return item;
  }
  return i->second;
}

}
