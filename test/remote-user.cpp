/******************************************************************************
 * Icinga 2                                                                   *
 * Copyright (C) 2012-2017 Icinga Development Team (https://www.icinga.com/)  *
 *                                                                            *
 * This program is free software; you can redistribute it and/or              *
 * modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 2             *
 * of the License, or (at your option) any later version.                     *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program; if not, write to the Free Software Foundation     *
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.             *
 ******************************************************************************/

#include "remote/apiuser.hpp"
#include <BoostTestTargetConfig.h>

using namespace icinga;

/*
#ifdef I2_DEBUG
class ApiUserTest {
public:
	static String getSalt(ApiUser::Ptr a) {
		return a->m_Salt;
	}
	static void setSalt(ApiUser::Ptr a, const String salt) {
		a->m_Salt = salt;
	}
	static String getPassword(ApiUser::Ptr a) {
		return a->m_Hashed_passwd;
	}
	static void setPassword(ApiUser::Ptr a, const String password) {
		a->m_Hashed_passwd = password;
	}
};
#endif
*/

BOOST_AUTO_TEST_SUITE(api_user)

BOOST_AUTO_TEST_CASE(password)
{
#ifndef I2_DEBUG
	std::cout << "Only enabled in Debug builds..." << std::endl;
#else
	ApiUser::Ptr user = new ApiUser();
	user->SetSalt("CCCP");
	user->SetPasswd(ApiUser::CreateHashedPasswordString("icinga2icinga", user->GetSalt()));

	BOOST_CHECK(user->ComparePassword("icinga2icinga"));
	BOOST_CHECK(!user->ComparePassword("2icinga"));

	user->SetSalt("BBBP");
	BOOST_CHECK(!user->ComparePassword("icinga2icinga"));
#endif
}

BOOST_AUTO_TEST_SUITE_END()
