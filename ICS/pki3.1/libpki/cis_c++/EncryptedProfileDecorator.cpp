#include <stdexcept>
#include <sstream>

#include "EncryptedProfileDecorator.hpp"

namespace Issac {

/** 문자열 값 읽기/쓰기 */
const std::string EncryptedProfileDecorator::get(std::string sec, 
  std::string attr)
{ 
  std::string out, in = _profile->get(sec, attr);
  _cipher.decodeAndDecrypt(out, in);
  return out;
}

void EncryptedProfileDecorator::set(std::string sec, std::string attr, 
  std::string val)
{
  std::string out;
  _cipher.encryptAndEncode(out, val);
  _profile->set(sec, attr, out);
}

} // end of namespace
