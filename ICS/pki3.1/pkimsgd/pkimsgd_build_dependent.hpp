/**
 * @file     pkimsgd_build_dependent.hpp
 *
 * @desc     BLD �ɼǿ� �������� ���Ǹ� ��� ���� ��
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_PKIMSGD_BUILD_DEPENDENT_HPP_
#define ISSAC_PKIMSGD_BUILD_DEPENDENT_HPP_

#define PROFILE_SECTION              "MSGD"

#ifdef BUILD_CA
  #include "PKIMessageDaemon.hpp"
  #include "CALoginProfile.hpp"
  #define MODULE_NAME                "CAMSGD"
  namespace Issac
  {
    typedef PKIMessageDaemon MESSAGE_DAEMON;
    typedef CALoginProfile LOGIN_PROFILE;
  };
#endif

#ifdef BUILD_RA
  #include "PKIMessageDaemon.hpp"
  #include "RALoginProfile.hpp"
  #define MODULE_NAME                "RAMSGD"
  namespace Issac
  {
    typedef PKIMessageDaemon MESSAGE_DAEMON;
    typedef RALoginProfile LOGIN_PROFILE;
  };
#endif

#endif
