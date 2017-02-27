/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#include <iomanip>

#include "DNS.hpp"

namespace DNS {

std::ostream& operator<<(std::ostream& os, Pkt_rcode pkt_rcode)
{
  char const* msg = "Unknown";
  switch (pkt_rcode) {
  case DNS::Pkt_rcode::NOERROR:
    msg = "NOERROR";
    break;
  case DNS::Pkt_rcode::FORMERR:
    msg = "FORMERR";
    break;
  case DNS::Pkt_rcode::SERVFAIL:
    msg = "SERVFAIL";
    break;
  case DNS::Pkt_rcode::NXDOMAIN:
    msg = "NXDOMAIN";
    break;
  case DNS::Pkt_rcode::NOTIMPL:
    msg = "NOTIMPL";
    break;
  case DNS::Pkt_rcode::REFUSED:
    msg = "REFUSED";
    break;
  case DNS::Pkt_rcode::YXDOMAIN:
    msg = "YXDOMAIN";
    break;
  case DNS::Pkt_rcode::YXRRSET:
    msg = "YXRRSET";
    break;
  case DNS::Pkt_rcode::NXRRSET:
    msg = "NXRRSET";
    break;
  case DNS::Pkt_rcode::NOTAUTH:
    msg = "NOTAUTH";
    break;
  case DNS::Pkt_rcode::NOTZONE:
    msg = "NOTZONE";
    break;
  case DNS::Pkt_rcode::INTERNAL:
    msg = "INTERNAL";
    break;
  }
  return os << msg;
};

template <>
std::vector<std::string> Rrlist<RR_type::TXT>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      auto rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          auto rdf = rr->_rdata_fields[j];
          if (rdf->_type == LDNS_RDF_TYPE_STR) {
            ret.push_back(rr_str(rdf));
          }
          else {
            LOG(WARNING) << "expecting TXT got:"
                         << static_cast<unsigned>(rdf->_type);
          }
        }
      }
    }
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::PTR>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      auto rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          auto rdf = rr->_rdata_fields[j];
          if (rdf->_type == LDNS_RDF_TYPE_DNAME) {
            ret.push_back(rr_name_str(rdf));
          }
          else {
            LOG(WARNING) << "expecting PTR got:"
                         << static_cast<unsigned>(rdf->_type);
            break;
          }
        }
      }
    }
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::A>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      ldns_rr const* rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          ldns_rdf const* rdf = rr->_rdata_fields[j];
          if (rdf->_type == LDNS_RDF_TYPE_A) {
            char str[INET_ADDRSTRLEN];
            PCHECK(inet_ntop(AF_INET, rdf->_data, str, sizeof str));
            ret.push_back(str);
          }
          else {
            LOG(WARNING) << "expecting A got:"
                         << static_cast<unsigned>(rdf->_type);
          }
        }
      }
    }
  }
  return ret;
}

template <RR_type T>
inline std::string Rrlist<T>::rr_name_str(ldns_rdf const* rdf) const
{
  if (rdf->_size > LDNS_MAX_DOMAINLEN) {
    LOG(WARNING) << "rdf size too large";
    return "<too long>";
  }
  if (rdf->_size == 1) {
    return "."; // root label
  }

  auto data = static_cast<unsigned char*>(rdf->_data);

  unsigned char src_pos = 0;
  unsigned char len = data[src_pos];

  std::ostringstream str;
  while ((len > 0) && (src_pos < rdf->_size)) {
    src_pos++;
    for (unsigned char i = 0; i < len; ++i) {
      unsigned char c = data[src_pos];
      if (c == '.' || c == ';' || c == '(' || c == ')' || c == '\\') {
        str << '\\' << c;
      }
      else if (!(isascii(c) && isgraph(c))) {
        str << "0x" << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(c);
      }
      else {
        str << c;
      }
      src_pos++;
    }
    if (src_pos < rdf->_size) {
      str << '.';
    }
    len = data[src_pos];
  }

  return str.str();
}
}
