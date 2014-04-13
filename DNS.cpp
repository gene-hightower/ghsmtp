/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "DNS.hpp"

namespace DNS {

std::unordered_map<DNS::Pkt_rcode, char const*> pkt_rcode_to_string{
  { Pkt_rcode::NOERROR, "NOERROR" },
  { Pkt_rcode::FORMERR, "FORMERR" },
  { Pkt_rcode::SERVFAIL, "SERVFAIL" },
  { Pkt_rcode::NXDOMAIN, "NXDOMAIN" },
  { Pkt_rcode::NOTIMPL, "NOTIMPL" },
  { Pkt_rcode::REFUSED, "REFUSED" },
  { Pkt_rcode::YXDOMAIN, "YXDOMAIN" },
  { Pkt_rcode::YXRRSET, "YXRRSET" },
  { Pkt_rcode::NXRRSET, "NXRRSET" },
  { Pkt_rcode::NOTAUTH, "NOTAUTH" },
  { Pkt_rcode::NOTZONE, "NOTZONE" },
};

std::unordered_map<DNS::RR_type, char const*> rr_type_to_string{
  { RR_type::A, "A" },
  { RR_type::CNAME, "CNAME" },
  { RR_type::PTR, "PTR" },
  { RR_type::MX, "MX" },
  { RR_type::TXT, "TXT" },
};

std::vector<std::string>
get_loop(enum ldns_enum_rdf_type t, ldns_rr_list* rrlst,
         std::function<std::string(ldns_rdf const* rdf)> f)
{
  std::vector<std::string> ret;
  if (rrlst) {
    for (unsigned i = 0; i < rrlst->_rr_count; ++i) {
      ldns_rr const* rr = rrlst->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          ldns_rdf const* rdf = rr->_rdata_fields[j];
          if (t == rdf->_type) {
            ret.push_back(f(rdf));
          } else {
            LOG(WARNING) << "expecting " << static_cast<unsigned>(t)
                         << " got:" << static_cast<unsigned>(rdf->_type);
          }
        }
      }
    }
  }
  return ret;
}
}
