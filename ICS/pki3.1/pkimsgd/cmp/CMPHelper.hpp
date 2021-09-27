/**
 * @file    CMPHelper.hpp
 *
 * @desc    CMP 처리에 도움을 주는 함수 모음
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2003.08.06
 */

#ifndef ISSAC_CMP_HELPER_HPP_
#define ISSAC_CMP_HELPER_HPP_

typedef ASNBitStr ReasonFlags;
class PKIPolicy;
typedef struct _KeyPolicy KeyPolicy;

namespace Issac
{

/**
 * 주어진 reason flag에 해당하는 reason code 값을 return 한다.
 * 단, reason flag에 복수개의 reason이 설정되어 있는 경우에는 그 중에서
 * 가장 작은 reason code 값을 리턴한다.
 *
 * @param *rf (In) Reason Flag 값(NULL이면 unspecified reason code를 리턴)
 * @return
 *    - 주어진 reason flag에 해당하는 reason code
 */
int ReasonFlagsToReasonCode(ReasonFlags * const reason);

/**
 * DB내의 PKIPolicy 정보를 이용하여 KeyPolicy를 생성한다.
 * 단 return값은 내부적으로 메모리가 할당되므로 반드시 free해 주어야 한다.
 *
 * @param *pkiPolicy  (In) DB내의 PKIPolicy 정보
 * @param  isRaPolicy (In) 만일 RA 정책인 경우, 해당 RA에게 이 정책이
 *                         허가되어 있는지 여부
 * @exception
 *  - Exception : 올바르지 않은 값이 들어있는 경우
 */
KeyPolicy *PKIPolicyToKeyPolicy (PKIPolicy *pkiPolicy, bool isRaPolicy = false);

}

#endif

