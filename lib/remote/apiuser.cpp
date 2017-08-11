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
#include "remote/apiuser.tcpp"
#include "base/configtype.hpp"
#include "base/tlsutility.hpp"

using namespace icinga;

REGISTER_TYPE(ApiUser);

void ApiUser::OnConfigLoaded(void)
{
	ObjectImpl<ApiUser>::OnConfigLoaded();

	Dictionary::Ptr passwd_dict = GetPasswordDict();

	if (passwd_dict != NULL) {
		m_Salt   = passwd_dict->Get("salt");
		m_Hashed_passwd = passwd_dict->Get("password");
	} else {
		m_Salt = RandomString(8);
		m_Hashed_passwd = CreateHashedPasswordString(this->GetPassword(), m_Salt, false);
	}
}

ApiUser::Ptr ApiUser::GetByClientCN(const String& cn)
{
	for (const ApiUser::Ptr& user : ConfigType::GetObjectsByType<ApiUser>()) {
		if (user->GetClientCN() == cn)
			return user;
	}

	return ApiUser::Ptr();
}

bool ApiUser::ComparePassword(String password) const {
	String other_passwd = CreateHashedPasswordString(password, this->m_Salt, false);

	const char *p1 = other_passwd.CStr();
	const char *p2 = this->m_Hashed_passwd.CStr();

	volatile char c = 0;

	for (size_t i=0; i<64; ++i)
		c |= p1[i] ^ p2[i];

	return (c == 0);
}

Dictionary::Ptr ApiUser::GetPasswordDict(void)
{
	String passwd = this->GetPasswordHash();
	if (passwd.IsEmpty() || passwd[0] != '$')
		return NULL;

	String::SizeType salt_begin = passwd.FindFirstOf('$', 1);
	String::SizeType passwd_begin = passwd.FindFirstOf('$', salt_begin+1);

	if (salt_begin == String::NPos || salt_begin == 1 || passwd_begin == String::NPos)
		return NULL;

	Dictionary::Ptr passwd_dict = new Dictionary();
	passwd_dict->Set("algorithm", passwd.SubStr(1, salt_begin-1));
	passwd_dict->Set("salt", passwd.SubStr(salt_begin+1, passwd_begin - salt_begin - 1));
	passwd_dict->Set("password", passwd.SubStr(passwd_begin+1));

	return passwd_dict;
}

String ApiUser::CreateHashedPasswordString(const String& password, const String& salt, const bool shadow)
{
	if (shadow)
		//Using /etc/shadow password format. The 5 means SHA256 is being used
		return String("$5$" + salt + "$" + PBKDF2_SHA256(password, salt, 1000));
	else
		return PBKDF2_SHA256(password, salt, 1000);

}
