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

std::unordered_map<DNS::Pkt_rcode, char const*> Pkt_rcode_to_string{
  { DNS::Pkt_rcode::NOERROR, "NOERROR" },
  { DNS::Pkt_rcode::FORMERR, "FORMERR" },
  { DNS::Pkt_rcode::SERVFAIL, "SERVFAIL" },
  { DNS::Pkt_rcode::NXDOMAIN, "NXDOMAIN" },
  { DNS::Pkt_rcode::NOTIMPL, "NOTIMPL" },
  { DNS::Pkt_rcode::REFUSED, "REFUSED" },
  { DNS::Pkt_rcode::YXDOMAIN, "YXDOMAIN" },
  { DNS::Pkt_rcode::YXRRSET, "YXRRSET" },
  { DNS::Pkt_rcode::NXRRSET, "NXRRSET" },
  { DNS::Pkt_rcode::NOTAUTH, "NOTAUTH" },
  { DNS::Pkt_rcode::NOTZONE, "NOTZONE" },
};
}
