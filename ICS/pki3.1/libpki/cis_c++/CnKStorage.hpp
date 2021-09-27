// CnKStorage.hpp: interface for the CnKStorage class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_CNK_STORAGE_HPP_
#define ISSAC_CNK_STORAGE_HPP_

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef _LIST_INCLUDED_
#include <list>
#define _LIST_INCLUDED_
#endif
#include <utility>
#include <string>
#include <vector>

#ifndef BOOST_SHARED_PTR_HPP_INCLUDED
#include <boost/shared_ptr.hpp>
#define BOOST_SHARED_PTR_HPP_INCLUDED
#endif

#include "CnK_define.hpp"

namespace Issac 
{

// 오류가 나면 Issac::Exception을 던지고 그것의 what()은 아래의 스트링 중 하나이다.
#define ER_S_CNK_STORAGE_NEED_MORE_ID_PASSWDS             "비공개키를 복구하는데는 더 많은 아이디와 패스워드가 필요합니다."
#define ER_S_CNK_STORAGE_FAIL_TO_LOAD_CERT                "공개키를 로드하는데 실패했습니다."
#define ER_S_CNK_STORAGE_FAIL_TO_LOAD_PRIKEY              "비공개키를 로드하는데 실패했습니다."
#define ER_S_CNK_STORAGE_INVALID_KEY_STORAGE_INFO_FILE    "키 저장 파일이 올바르지 않습니다."
#define ER_S_CNK_STORAGE_FAIL_TO_DECRYPT_PRIKEY           "비공개키를 복구하는데 실패했습니다."

/**
 * Default 인증서, 비공개키 저장소에 대한 구현
 * 현재 유효한 인증서에 대해서는 또 다른 저장소를 둘 수 있도록 virtual로 
 * 처리하지만 키히스토리는 그냥 동일하게 사용하도록 했다.
 * 결과적으로 _loadPrivKey는 계승된 함수에서도 동일하게 적용한다. - 조현래
 */
class CnKStorage
{
public:
  CnKStorage() {}
  virtual ~CnKStorage() {}

  /**
   * 비공개키를 로드한다.
   */
  virtual CnKSharedPtrs loadCnKs(
    std::vector< std::pair<std::string, std::string> > id_passwds, 
    std::string certFile, std::string prikeyFile, std::string keyhistFile);

protected:
  std::vector< std::pair<std::string, std::string> > _id_passwds;
  std::string _certFile;
  std::string _prikeyFile;
  std::string _keyhistFile;

  /**
   * 기본 비공개키 저장소로부터 인증서와 비공개키를 로드
   */
  PrivateKeyInfoSharedPtr _loadPrivateKey();

  /**
   * 저장소로부터 기존 인증서와 비공개키를 가져온다.
   * @param cnks (In, Out) 기존 인증서와 비공개키를 저장할 CertSharedPtrs 구조체
   *                       기존의 값에 append되어 추가된다.
   */
  void _loadPrevCnKs(CnKSharedPtrs &cnks);
};

}

#endif // ISSAC_CNK_STORAGE_HPP_
