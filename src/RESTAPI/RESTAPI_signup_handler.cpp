//
// Created by stephane bourque on 2022-02-20.
//

#include "RESTAPI_signup_handler.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"
#include "StorageService.h"
#include "framework/MicroServiceFuncs.h"

#define __DBG__ std::cout << __LINE__ << std::endl;
namespace OpenWifi {


	void RESTAPI_signup_handler::DoPost() {
		auto UserName = GetParameter("email");
		auto signupUUID = GetParameter("signupUUID");
		auto owner = GetParameter("owner");
		auto operatorName = GetParameter("operatorName");
		auto resend = GetBoolParameter("resend", false);
		if (UserName.empty() || signupUUID.empty() || owner.empty() || operatorName.empty()) {
			Logger().error("Signup requires: email, signupUUID, operatorName, and owner.");
			return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
		}

		if (!Utils::ValidEMailAddress(UserName)) {
			return BadRequest(RESTAPI::Errors::InvalidEmailAddress);
		}
		Logger_.information(fmt::format("SIGNUP-REQUEST({}): Signup request for {}", Request->clientAddress().toString(),UserName));

		SecurityObjects::UserInfo NewSub;
		bool ExistingUser = StorageService()->SubDB().GetUserByEmail(UserName, NewSub);

		if (ExistingUser) {
			if (NewSub.waitingForEmailCheck == false) {
				return BadRequest(RESTAPI::Errors::SignupAlreadySigned);
			} else if (resend == true) {
				NewSub.modified = OpenWifi::Now();
				StorageService()->SubDB().UpdateUserInfo(NewSub.email, NewSub.id, NewSub);
			} else {
				return BadRequest(RESTAPI::Errors::SignupEmailCheck);
			}
		} else {
			// first time signup: create the subscriber
			NewSub.signingUp = operatorName + ":" + signupUUID;
			NewSub.waitingForEmailCheck = true;
			NewSub.name = UserName;
			NewSub.modified = OpenWifi::Now();
			NewSub.creationDate = OpenWifi::Now();
			NewSub.id = MicroServiceCreateUUID();
			NewSub.email = UserName;
			NewSub.userRole = SecurityObjects::SUBSCRIBER;
			NewSub.changePassword = true;
			NewSub.owner = owner;
			StorageService()->SubDB().CreateRecord(NewSub);
		}

		SecurityObjects::ActionLink NewLink;
		NewLink.action = OpenWifi::SecurityObjects::LinkActions::SUB_SIGNUP;
		NewLink.id = MicroServiceCreateUUID();
		NewLink.userId = NewSub.id;
		NewLink.created = OpenWifi::Now();
		NewLink.expires = NewLink.created + (1 * 60 * 60); // 1 hour
		NewLink.userAction = false;
		StorageService()->ActionLinksDB().CreateAction(NewLink);

		Poco::JSON::Object Answer;
		NewSub.to_json(Answer);
		return ReturnObject(Answer);
	}

	void RESTAPI_signup_handler::DoPut() {
		// TODO
	}

} // namespace OpenWifi