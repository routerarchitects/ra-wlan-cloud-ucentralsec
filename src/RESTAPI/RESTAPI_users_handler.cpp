//
// Created by stephane bourque on 2021-06-21.
//

#include "RESTAPI_users_handler.h"
#include "ACLProcessor.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "StorageService.h"

namespace OpenWifi {

	namespace {
		inline bool IsAdminUserCaller(const SecurityObjects::UserInfo &User) {
			return User.userRole == SecurityObjects::ROOT || User.userRole == SecurityObjects::ADMIN;
		}
	}

	void RESTAPI_users_handler::DoGet() {

		bool IdOnly = (GetParameter("idOnly", "false") == "true");
		auto nameSearch = GetParameter("nameSearch");
		auto emailSearch = GetParameter("emailSearch");

		if (!IsAdminUserCaller(UserInfo_.userinfo)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		std::string baseQuery;
		if (!nameSearch.empty() || !emailSearch.empty()) {
			if (!nameSearch.empty())
				baseQuery = fmt::format(" Lower(name) like('%{}%') ",
										ORM::Escape(Poco::toLower(nameSearch)));
			if (!emailSearch.empty())
				baseQuery += baseQuery.empty()
								 ? fmt::format(" Lower(email) like('%{}%') ",
											   ORM::Escape(Poco::toLower(emailSearch)))
								 : fmt::format(" and Lower(email) like('%{}%') ",
											   ORM::Escape(Poco::toLower(emailSearch)));
		}

		if (UserInfo_.userinfo.userRole == SecurityObjects::ADMIN) {
			auto AdminScope = fmt::format(" createdby='{}' ", ORM::Escape(UserInfo_.userinfo.id));
			baseQuery = baseQuery.empty() ? AdminScope : fmt::format("{} and {}", AdminScope, baseQuery);
		}

		if (QB_.Select.empty()) {
			SecurityObjects::UserInfoList Users;
			if (StorageService()->UserDB().GetUsers(QB_.Offset, QB_.Limit, Users.users,
													baseQuery)) {
				for (auto &i : Users.users) {
					Sanitize(UserInfo_, i);
				}
				if (IdOnly) {
					Poco::JSON::Array Arr;
					for (const auto &i : Users.users)
						Arr.add(i.id);
					Poco::JSON::Object Answer;
					Answer.set("users", Arr);
					return ReturnObject(Answer);
				}
			}
			Poco::JSON::Object Answer;
			Users.to_json(Answer);
			return ReturnObject(Answer);
		} else {
			SecurityObjects::UserInfoList Users;
			for (auto &i : SelectedRecords()) {
				SecurityObjects::UserInfo UInfo;
				if (StorageService()->UserDB().GetUserById(i, UInfo)) {
					if (!ACLProcessor::CanReadUserRecord(UserInfo_.userinfo, UInfo)) {
						continue;
					}
					Sanitize(UserInfo_, UInfo);
					Users.users.emplace_back(UInfo);
				}
			}
			Poco::JSON::Object Answer;
			Users.to_json(Answer);
			return ReturnObject(Answer);
		}
	}
} // namespace OpenWifi
