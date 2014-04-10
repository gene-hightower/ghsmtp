/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

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

#include "SPF.hpp"

namespace SPF {

std::unordered_map<Result, char const*> result_to_string{
  { SPF::Result::INVALID, "INVALID" },
  { SPF::Result::NEUTRAL, "NEUTRAL" },
  { SPF::Result::PASS, "PASS" },
  { SPF::Result::FAIL, "FAIL" },
  { SPF::Result::SOFTFAIL, "SOFTFAIL" },
  { SPF::Result::NONE, "NONE" },
  { SPF::Result::TEMPERROR, "TEMPERROR" },
  { SPF::Result::PERMERROR, "PERMERROR" },
};
}
