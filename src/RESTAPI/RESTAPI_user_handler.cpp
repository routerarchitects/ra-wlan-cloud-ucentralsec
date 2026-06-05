//
// Created by stephane bourque on 2021-06-21.
//

#include "RESTAPI_user_handler.h"
#include "ACLProcessor.h"
#include "AuthService.h"
#include "MFAServer.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "SMSSender.h"
#include "SMTPMailerService.h"
#include "StorageService.h"
#include "TotpCache.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/ow_constants.h"

#include <algorithm>
#include <array>

namespace OpenWifi {

	namespace {
		enum class PasswordUpdateStatus { Applied, InvalidPassword, Rejected };
		enum class MfaUpdateStatus {
			Applied,
			BadMethod,
			SmsNotEnabled,
			EmailNotEnabled,
			NeedMobileNumber,
			AuthenticatorIncomplete
		};

		inline bool IsSelfServiceCaller(const SecurityObjects::UserInfo &User) {
			return User.userRole != SecurityObjects::ROOT &&
				   User.userRole != SecurityObjects::ADMIN;
		}

		inline bool IsAllowedSelfServiceField(const std::string &Field) {
			static constexpr std::array<const char *, 7> AllowedFields{
				"name", "description", "location", "locale", "changePassword",
				"currentPassword", "userTypeProprietaryInfo"};
			return std::find(AllowedFields.begin(), AllowedFields.end(), Field) !=
				   AllowedFields.end();
		}

		inline bool HasOnlyAllowedSelfServiceFields(
			const Poco::JSON::Object::Ptr &RawObject) {
			for (const auto &Entry : *RawObject) {
				if (!IsAllowedSelfServiceField(Entry.first)) {
					return false;
				}
			}
			return true;
		}

		bool HandleResetMFA(const SecurityObjects::UserInfoAndPolicy &Caller,
							const std::string &Id, SecurityObjects::UserInfo &Existing,
							Poco::JSON::Object &ModifiedObject) {
			Existing.userTypeProprietaryInfo.mfa.enabled = false;
			Existing.userTypeProprietaryInfo.mfa.method.clear();
			Existing.userTypeProprietaryInfo.mobiles.clear();
			Existing.modified = OpenWifi::Now();
			Existing.notes.push_back(
				SecurityObjects::NoteInfo{.created = OpenWifi::Now(),
										  .createdBy = Caller.userinfo.email,
										  .note = "MFA Reset by " + Caller.userinfo.email});
			auto UpdateId = Id;
			if (!StorageService()->UserDB().UpdateUserInfo(Caller.userinfo.email, UpdateId,
														  Existing)) {
				return false;
			}
			SecurityObjects::UserInfo NewUserInfo;
			if (!StorageService()->UserDB().GetUserById(Id, NewUserInfo)) {
				return false;
			}
			Sanitize(Caller, NewUserInfo);
			NewUserInfo.to_json(ModifiedObject);
			return true;
		}

		bool HandleForgotPassword(Poco::Logger &Log, const std::string &CallerAddress,
								  SecurityObjects::UserInfo &Existing) {
			Existing.changePassword = true;
			Log.information(fmt::format("FORGOTTEN-PASSWORD({}): Request for {}",
										CallerAddress, Existing.email));

			SecurityObjects::ActionLink NewLink;
			NewLink.action = OpenWifi::SecurityObjects::LinkActions::FORGOT_PASSWORD;
			NewLink.id = MicroServiceCreateUUID();
			NewLink.userId = Existing.id;
			NewLink.created = OpenWifi::Now();
			NewLink.expires = NewLink.created + (24 * 60 * 60);
			NewLink.userAction = true;
			StorageService()->ActionLinksDB().CreateAction(NewLink);
			return true;
		}

		bool ValidateUpdatePayload(const Poco::JSON::Object::Ptr &RawObject) {
			if (RawObject->has("userRole") &&
				SecurityObjects::UserTypeFromString(RawObject->get("userRole").toString()) ==
					SecurityObjects::UNKNOWN) {
				return false;
			}
			return true;
		}

		void ApplyOwnerUpdate(const SecurityObjects::UserInfoAndPolicy &Caller,
							  const Poco::JSON::Object::Ptr &RawObject,
							  SecurityObjects::UserInfo &Existing) {
			if (RawObject->has("owner") && Caller.userinfo.userRole == SecurityObjects::ROOT &&
				Existing.owner.empty()) {
				RESTAPIHandler::AssignIfPresent(RawObject, "owner", Existing.owner);
			}
		}

		void ApplyProfileFields(const Poco::JSON::Object::Ptr &RawObject,
								SecurityObjects::UserInfo &Existing) {
			RESTAPIHandler::AssignIfPresent(RawObject, "name", Existing.name);
			RESTAPIHandler::AssignIfPresent(RawObject, "description", Existing.description);
			RESTAPIHandler::AssignIfPresent(RawObject, "location", Existing.location);
			RESTAPIHandler::AssignIfPresent(RawObject, "locale", Existing.locale);
			RESTAPIHandler::AssignIfPresent(RawObject, "changePassword", Existing.changePassword);
		}

		void ApplyAdminStatusFields(const Poco::JSON::Object::Ptr &RawObject,
									SecurityObjects::UserInfo &Existing) {
			RESTAPIHandler::AssignIfPresent(RawObject, "suspended", Existing.suspended);
			RESTAPIHandler::AssignIfPresent(RawObject, "blackListed", Existing.blackListed);
		}

		bool ApplyRoleChange(const SecurityObjects::UserInfoAndPolicy &Caller,
							 SecurityObjects::UserInfo &Existing,
							 const Poco::JSON::Object::Ptr &RawObject) {
			if (!RawObject->has("userRole")) {
				return true;
			}

			auto NewRole =
				SecurityObjects::UserTypeFromString(RawObject->get("userRole").toString());
			if (NewRole != Existing.userRole) {
				if (!ACLProcessor::CanChangeUserRole(Caller.userinfo, Existing, NewRole)) {
					return false;
				}
				Existing.userRole = NewRole;
			}
			return true;
		}

		void AppendNotes(const SecurityObjects::UserInfoAndPolicy &Caller,
						 const Poco::JSON::Object::Ptr &RawObject,
						 SecurityObjects::UserInfo &Existing) {
			if (!RawObject->has("notes")) {
				return;
			}

			SecurityObjects::NoteInfoVec NIV = RESTAPI_utils::to_object_array<SecurityObjects::NoteInfo>(
				RawObject->get("notes").toString());
			for (const auto &i : NIV) {
				SecurityObjects::NoteInfo ii{.created = (uint64_t)OpenWifi::Now(),
											 .createdBy = Caller.userinfo.email,
											 .note = i.note};
				Existing.notes.push_back(ii);
			}
		}

		PasswordUpdateStatus ApplyPasswordChange(const Poco::JSON::Object::Ptr &RawObject,
												 SecurityObjects::UserInfo &Existing) {
			if (!RawObject->has("currentPassword")) {
				return PasswordUpdateStatus::Applied;
			}
			const auto Password = RawObject->get("currentPassword").toString();
			if (!AuthService()->ValidatePassword(Password)) {
				return PasswordUpdateStatus::InvalidPassword;
			}
			if (!AuthService()->SetPassword(Password, Existing)) {
				return PasswordUpdateStatus::Rejected;
			}
			return PasswordUpdateStatus::Applied;
		}

		MfaUpdateStatus ApplyMfaChange(const SecurityObjects::UserInfoAndPolicy &Caller,
									   const SecurityObjects::UserInfo &NewUser,
									   bool HasMfaUpdate, SecurityObjects::UserInfo &Existing) {
			if (!HasMfaUpdate) {
				return MfaUpdateStatus::Applied;
			}

			if (NewUser.userTypeProprietaryInfo.mfa.enabled) {
				if (!MFAMETHODS::Validate(NewUser.userTypeProprietaryInfo.mfa.method)) {
					return MfaUpdateStatus::BadMethod;
				}

				if (NewUser.userTypeProprietaryInfo.mfa.enabled &&
					NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::SMS &&
					!SMSSender()->Enabled()) {
					return MfaUpdateStatus::SmsNotEnabled;
				}

				if (NewUser.userTypeProprietaryInfo.mfa.enabled &&
					NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::EMAIL &&
					!SMTPMailerService()->Enabled()) {
					return MfaUpdateStatus::EmailNotEnabled;
				}

				Existing.userTypeProprietaryInfo.mfa.method =
					NewUser.userTypeProprietaryInfo.mfa.method;
				Existing.userTypeProprietaryInfo.mfa.enabled = true;

				if (NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::SMS) {
					if (NewUser.userTypeProprietaryInfo.mobiles.empty()) {
						return MfaUpdateStatus::NeedMobileNumber;
					}
					if (!SMSSender()->IsNumberValid(
							NewUser.userTypeProprietaryInfo.mobiles[0].number,
							Caller.userinfo.email)) {
						return MfaUpdateStatus::NeedMobileNumber;
					}
					Existing.userTypeProprietaryInfo.mobiles =
						NewUser.userTypeProprietaryInfo.mobiles;
					Existing.userTypeProprietaryInfo.mobiles[0].verified = true;
					Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				} else if (NewUser.userTypeProprietaryInfo.mfa.method ==
						   MFAMETHODS::AUTHENTICATOR) {
					std::string Secret;
					Existing.userTypeProprietaryInfo.mobiles.clear();
					if (Existing.userTypeProprietaryInfo.authenticatorSecret.empty() &&
						TotpCache()->CompleteValidation(Caller.userinfo, false, Secret)) {
						Existing.userTypeProprietaryInfo.authenticatorSecret = Secret;
					} else if (!Existing.userTypeProprietaryInfo.authenticatorSecret.empty()) {
						// we allow someone to use their old secret
					} else {
						return MfaUpdateStatus::AuthenticatorIncomplete;
					}
				} else if (NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::EMAIL) {
					Existing.userTypeProprietaryInfo.mobiles.clear();
					Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				}
			} else {
				Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				Existing.userTypeProprietaryInfo.mobiles.clear();
				Existing.userTypeProprietaryInfo.mfa.enabled = false;
			}

			return MfaUpdateStatus::Applied;
		}

		bool BuildUpdatedUserResponse(const SecurityObjects::UserInfoAndPolicy &Caller,
									  const std::string &Id, Poco::JSON::Object &ModifiedObject) {
			SecurityObjects::UserInfo NewUserInfo;
			if (!StorageService()->UserDB().GetUserById(Id, NewUserInfo)) {
				return false;
			}
			Sanitize(Caller, NewUserInfo);
			NewUserInfo.to_json(ModifiedObject);
			return true;
		}
	}

	void RESTAPI_user_handler::DoGet() {

		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		Poco::toLowerInPlace(Id);
		std::string Arg;
		SecurityObjects::UserInfo UInfo;
		if (HasParameter("byEmail", Arg) && Arg == "true") {
			if (!StorageService()->UserDB().GetUserByEmail(Id, UInfo)) {
				return NotFound();
			}
		} else if (!StorageService()->UserDB().GetUserById(Id, UInfo)) {
			return NotFound();
		}

		if (!ACLProcessor::CanReadUserRecord(UserInfo_.userinfo, UInfo)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		Poco::JSON::Object UserInfoObject;
		Sanitize(UserInfo_, UInfo);
		UInfo.to_json(UserInfoObject);
		ReturnObject(UserInfoObject);
	}

	void RESTAPI_user_handler::DoDelete() {

		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		SecurityObjects::UserInfo UInfo;
		if (!StorageService()->UserDB().GetUserById(Id, UInfo)) {
			return NotFound();
		}

		if (!ACLProcessor::CanDeleteUserRecord(UserInfo_.userinfo, UInfo)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		if (!StorageService()->UserDB().DeleteUser(UserInfo_.userinfo.email, Id)) {
			return NotFound();
		}

		AuthService()->DeleteUserFromCache(Id);
		StorageService()->AvatarDB().DeleteAvatar(UserInfo_.userinfo.email, Id);
		StorageService()->PreferencesDB().DeletePreferences(UserInfo_.userinfo.email, Id);
		StorageService()->UserTokenDB().RevokeAllTokens(Id);
		StorageService()->ApiKeyDB().RemoveAllApiKeys(Id);
		Logger_.information(
			fmt::format("User '{}' deleted by '{}'.", Id, UserInfo_.userinfo.email));
		OK();
	}

	void RESTAPI_user_handler::DoPost() {

		std::string Id = GetBinding("id", "");
		if (Id != "0") {
			return BadRequest(RESTAPI::Errors::IdMustBe0);
		}

		SecurityObjects::UserInfo NewUser;
		const auto &RawObject = ParsedBody_;
		if (!NewUser.from_json(RawObject)) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}

		if (NewUser.userRole == SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::InvalidUserRole);
		}

		NewUser.createdBy = UserInfo_.userinfo.id;
		if (UserInfo_.userinfo.userRole == SecurityObjects::ROOT) {
			NewUser.owner = GetParameter("entity", "");
		} else {
			NewUser.owner = UserInfo_.userinfo.owner;
		}

		if (!ACLProcessor::CanCreateUserRecord(UserInfo_.userinfo, NewUser)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		Poco::toLowerInPlace(NewUser.email);
		if (!Utils::ValidEMailAddress(NewUser.email)) {
			return BadRequest(RESTAPI::Errors::InvalidEmailAddress);
		}

		SecurityObjects::UserInfo Existing;
		if (StorageService()->SubDB().GetUserByEmail(NewUser.email, Existing)) {
			return BadRequest(RESTAPI::Errors::UserAlreadyExists);
		}

		if (!NewUser.currentPassword.empty()) {
			if (!AuthService()->ValidatePassword(NewUser.currentPassword)) {
				return BadRequest(RESTAPI::Errors::InvalidPassword);
			}
		}

		if (NewUser.name.empty())
			NewUser.name = NewUser.email;

		//  You cannot enable MFA during user creation
		NewUser.userTypeProprietaryInfo.mfa.enabled = false;
		NewUser.userTypeProprietaryInfo.mfa.method = "";
		NewUser.userTypeProprietaryInfo.mobiles.clear();
		NewUser.userTypeProprietaryInfo.authenticatorSecret.clear();
		NewUser.validated = true;

		if (!StorageService()->UserDB().CreateUser(NewUser.email, NewUser)) {
			Logger_.information(fmt::format("Could not add user '{}'.", NewUser.email));
			return BadRequest(RESTAPI::Errors::RecordNotCreated);
		}

		if (GetParameter("email_verification", "") == "true") {
			if (AuthService::VerifyEmail(NewUser))
				Logger_.information(
					fmt::format("Verification e-mail requested for {}", NewUser.email));
			StorageService()->UserDB().UpdateUserInfo(UserInfo_.userinfo.email, NewUser.id,
													  NewUser);
		}

		if (!StorageService()->UserDB().GetUserByEmail(NewUser.email, NewUser)) {
			Logger_.information(fmt::format("User '{}' but not retrieved.", NewUser.email));
			return NotFound();
		}

		Poco::JSON::Object UserInfoObject;
		Sanitize(UserInfo_, NewUser);
		NewUser.to_json(UserInfoObject);
		ReturnObject(UserInfoObject);
		Logger_.information(fmt::format("User '{}' has been added by '{}')", NewUser.email,
										UserInfo_.userinfo.email));
	}

	void RESTAPI_user_handler::DoPut() {

		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		SecurityObjects::UserInfo Existing;
		if (!StorageService()->UserDB().GetUserById(Id, Existing)) {
			return NotFound();
		}

		if (!ACLProcessor::CanModifyUserRecord(UserInfo_.userinfo, Existing)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		if (GetParameter("resetMFA", "") == "true") {
			if (!ACLProcessor::CanResetUserMFA(UserInfo_.userinfo, Existing)) {
				return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
			}

			Poco::JSON::Object ModifiedObject;
			if (!HandleResetMFA(UserInfo_, Id, Existing, ModifiedObject)) {
				return BadRequest(RESTAPI::Errors::RecordNotUpdated);
			}
			return ReturnObject(ModifiedObject);
		}

		if (GetParameter("forgotPassword", "") == "true") {
			HandleForgotPassword(Logger(), Request->clientAddress().toString(), Existing);
			return OK();
		}

		SecurityObjects::UserInfo NewUser;
		const auto &RawObject = ParsedBody_;
		if (!NewUser.from_json(RawObject)) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}

		if (!ValidateUpdatePayload(RawObject)) {
			return BadRequest(RESTAPI::Errors::InvalidUserRole);
		}

		if (IsSelfServiceCaller(UserInfo_.userinfo) &&
			!HasOnlyAllowedSelfServiceFields(RawObject)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		ApplyOwnerUpdate(UserInfo_, RawObject, Existing);
		ApplyProfileFields(RawObject, Existing);
		ApplyAdminStatusFields(RawObject, Existing);

		if (!ApplyRoleChange(UserInfo_, Existing, RawObject)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		AppendNotes(UserInfo_, RawObject, Existing);

		switch (ApplyPasswordChange(RawObject, Existing)) {
		case PasswordUpdateStatus::InvalidPassword:
			return BadRequest(RESTAPI::Errors::InvalidPassword);
		case PasswordUpdateStatus::Rejected:
			return BadRequest(RESTAPI::Errors::PasswordRejected);
		case PasswordUpdateStatus::Applied:
			break;
		}

		if (GetParameter("email_verification", "") == "true") {
			if (AuthService::VerifyEmail(Existing))
				Logger_.information(
					fmt::format("Verification e-mail requested for {}", Existing.email));
		}

		switch (ApplyMfaChange(UserInfo_, NewUser, RawObject->has("userTypeProprietaryInfo"),
							   Existing)) {
		case MfaUpdateStatus::BadMethod:
			return BadRequest(RESTAPI::Errors::BadMFAMethod);
		case MfaUpdateStatus::SmsNotEnabled:
			return BadRequest(RESTAPI::Errors::SMSMFANotEnabled);
		case MfaUpdateStatus::EmailNotEnabled:
			return BadRequest(RESTAPI::Errors::EMailMFANotEnabled);
		case MfaUpdateStatus::NeedMobileNumber:
			return BadRequest(RESTAPI::Errors::NeedMobileNumber);
		case MfaUpdateStatus::AuthenticatorIncomplete:
			return BadRequest(RESTAPI::Errors::AuthenticatorVerificationIncomplete);
		case MfaUpdateStatus::Applied:
			break;
		}

		Existing.modified = OpenWifi::Now();
		if (StorageService()->UserDB().UpdateUserInfo(UserInfo_.userinfo.email, Id, Existing)) {
			Poco::JSON::Object ModifiedObject;
			if (!BuildUpdatedUserResponse(UserInfo_, Id, ModifiedObject)) {
				return NotFound();
			}
			return ReturnObject(ModifiedObject);
		}
		return BadRequest(RESTAPI::Errors::RecordNotUpdated);
	}
} // namespace OpenWifi
