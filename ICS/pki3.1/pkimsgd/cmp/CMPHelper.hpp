/**
 * @file    CMPHelper.hpp
 *
 * @desc    CMP ó���� ������ �ִ� �Լ� ����
 * @author  ������(hrcho@pentasecurity.com)
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
 * �־��� reason flag�� �ش��ϴ� reason code ���� return �Ѵ�.
 * ��, reason flag�� �������� reason�� �����Ǿ� �ִ� ��쿡�� �� �߿���
 * ���� ���� reason code ���� �����Ѵ�.
 *
 * @param *rf (In) Reason Flag ��(NULL�̸� unspecified reason code�� ����)
 * @return
 *    - �־��� reason flag�� �ش��ϴ� reason code
 */
int ReasonFlagsToReasonCode(ReasonFlags * const reason);

/**
 * DB���� PKIPolicy ������ �̿��Ͽ� KeyPolicy�� �����Ѵ�.
 * �� return���� ���������� �޸𸮰� �Ҵ�ǹǷ� �ݵ�� free�� �־�� �Ѵ�.
 *
 * @param *pkiPolicy  (In) DB���� PKIPolicy ����
 * @param  isRaPolicy (In) ���� RA ��å�� ���, �ش� RA���� �� ��å��
 *                         �㰡�Ǿ� �ִ��� ����
 * @exception
 *  - Exception : �ùٸ��� ���� ���� ����ִ� ���
 */
KeyPolicy *PKIPolicyToKeyPolicy (PKIPolicy *pkiPolicy, bool isRaPolicy = false);

}

#endif

