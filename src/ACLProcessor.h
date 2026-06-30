//
// Created by stephane bourque on 2021-11-12.
//

#ifndef OWSEC_ACLPROCESSOR_H
#define OWSEC_ACLPROCESSOR_H

#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

	class ACLProcessor {
	  public:
		enum ACL_OPS { READ, MODIFY, DELETE, CREATE };

		static inline bool IsRoot(const SecurityObjects::UserInfo &User) {
			return User.userRole == SecurityObjects::ROOT;
		}

		static inline bool IsAdmin(const SecurityObjects::UserInfo &User) {
			return User.userRole == SecurityObjects::ADMIN;
		}

		static inline bool IsSelf(const SecurityObjects::UserInfo &User,
								  const SecurityObjects::UserInfo &Target) {
			return User.id == Target.id;
		}

		static inline bool WasCreatedBy(const SecurityObjects::UserInfo &User,
										const SecurityObjects::UserInfo &Target) {
			return !Target.createdBy.empty() && Target.createdBy == User.id;
		}

		static inline bool IsNonRootTarget(const SecurityObjects::UserInfo &Target) {
			return Target.userRole != SecurityObjects::ROOT;
		}

		static inline bool Can(const SecurityObjects::UserInfo &User,
							   const SecurityObjects::UserInfo &Target, ACL_OPS Op) {
			if (Op == READ) {
				return User.userRole == SecurityObjects::ROOT ||
					   User.userRole == SecurityObjects::ADMIN ||
					   User.userRole == SecurityObjects::PARTNER;
			}
			if (User.id == Target.id) {
				if (Op == DELETE) return User.userRole != SecurityObjects::ROOT;
				return true;
			}
			if (User.userRole == SecurityObjects::ROOT) return true;
			if (User.userRole == SecurityObjects::ADMIN || User.userRole == SecurityObjects::SYSTEM) {
				return Target.userRole != SecurityObjects::ROOT && Target.userRole != SecurityObjects::PARTNER;
			}
			if (User.userRole == SecurityObjects::PARTNER) return Target.userRole != SecurityObjects::ROOT;
			if (User.userRole == SecurityObjects::SUBSCRIBER) return false;
			if (Op == DELETE && (User.userRole == SecurityObjects::CSR || User.userRole == SecurityObjects::INSTALLER)) return false;
			return User.userRole == Target.userRole;
		}

		static inline bool CanReadUserRecord(const SecurityObjects::UserInfo &User,
											const SecurityObjects::UserInfo &Target) {
			if (IsRoot(User)) return true;
			if (IsSelf(User, Target)) return IsNonRootTarget(Target);
			return IsAdmin(User) && WasCreatedBy(User, Target);
		}

		static inline bool CanCreateUserRecord(const SecurityObjects::UserInfo &User,
											   const SecurityObjects::UserInfo &Target) {
			if (IsRoot(User)) return true;
			return IsAdmin(User) && IsNonRootTarget(Target) && Target.userRole != SecurityObjects::PARTNER;
		}

		static inline bool CanDeleteUserRecord(const SecurityObjects::UserInfo &User,
											   const SecurityObjects::UserInfo &Target) {
			if (IsSelf(User, Target)) return false;
			if (IsRoot(User)) return true;
			return IsAdmin(User) && WasCreatedBy(User, Target) && IsNonRootTarget(Target);
		}

		static inline bool CanModifyUserRecord(const SecurityObjects::UserInfo &User,
											   const SecurityObjects::UserInfo &Target) {
			if (IsRoot(User)) return true;
			if (IsSelf(User, Target)) return IsNonRootTarget(Target);
			return IsAdmin(User) && IsNonRootTarget(Target) && WasCreatedBy(User, Target);
		}

		static inline bool CanResetUserMFA(const SecurityObjects::UserInfo &User,
										   const SecurityObjects::UserInfo &Target) {
			return CanModifyUserRecord(User, Target);
		}

		static inline bool CanChangeUserRole(const SecurityObjects::UserInfo &User,
											 const SecurityObjects::UserInfo &Target,
											 SecurityObjects::USER_ROLE NewRole) {
			if (IsSelf(User, Target)) return false;
			if (IsRoot(User)) return true;
			return IsAdmin(User) && NewRole != SecurityObjects::ROOT && IsNonRootTarget(Target) &&
				   WasCreatedBy(User, Target);
		}

	  private:
	};

} // namespace OpenWifi

#endif // OWSEC_ACLPROCESSOR_H
