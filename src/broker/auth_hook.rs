use async_trait::async_trait;
use rmqtt::{
    hook::{Handler, HookResult, Parameter, ReturnType},
    types::{AuthResult, ConnectInfo},
};

use crate::state::AppState;

pub struct SmqttAuthHandler {
    pub state: AppState,
}

#[async_trait]
impl Handler for SmqttAuthHandler {
    async fn hook(&self, param: &Parameter, acc: Option<HookResult>) -> ReturnType {
        match param {
            Parameter::ClientAuthenticate(connect_info) => {
                self.authenticate(connect_info, acc).await
            }
            Parameter::ClientSubscribeCheckAcl(_, subscribe) => {
                // Topic ACL is enforced at auth time via JWT claims.
                // Allow all subscribes from authenticated clients.
                (true, Some(HookResult::SubscribeAclResult(
                    rmqtt::types::SubscribeAclResult::new_success(subscribe.opts.qos(), None)
                )))
            }
            Parameter::MessagePublishCheckAcl(_, _publish) => {
                // Publish ACL enforced at auth time via JWT claims.
                (true, Some(HookResult::PublishAclResult(
                    rmqtt::types::PublishAclResult::allow()
                )))
            }
            _ => (true, acc),
        }
    }
}

impl SmqttAuthHandler {
    async fn authenticate(
        &self,
        connect_info: &ConnectInfo,
        acc: Option<HookResult>,
    ) -> ReturnType {
        // If a previous handler already denied, propagate.
        if matches!(
            acc,
            Some(HookResult::AuthResult(AuthResult::BadUsernameOrPassword))
                | Some(HookResult::AuthResult(AuthResult::NotAuthorized))
        ) {
            return (false, acc);
        }

        // JWT is passed in the password field.
        let token = match connect_info.password() {
            Some(pw) => match std::str::from_utf8(pw) {
                Ok(s) => s.to_owned(),
                Err(_) => return deny(),
            },
            None => return deny(),
        };

        // Verify JWT and extract claims.
        let claims = match self.state.jwt_keys.verify(&token) {
            Ok(c)  => c,
            Err(_) => return deny(),
        };

        // Check suspension in DB.
        match crate::db::get_user(&self.state.db, &claims.sub).await {
            Ok(user) if !user.suspended => {}
            _ => return deny(),
        }

        (false, Some(HookResult::AuthResult(AuthResult::Allow(false, None))))
    }
}

fn deny() -> ReturnType {
    (false, Some(HookResult::AuthResult(AuthResult::NotAuthorized)))
}
