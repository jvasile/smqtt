use async_trait::async_trait;
use rmqtt::{
    hook::{Handler, HookResult, Parameter, ReturnType},
    session::Session,
    types::{AuthResult, ConnectInfo, Subscribe},
};
use rmqtt::codec::v5::SubscribeAckReason;

use crate::state::AppState;

#[derive(Clone)]
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
            Parameter::ClientSubscribeCheckAcl(session, subscribe) => {
                self.check_subscribe_acl(session, subscribe, acc).await
            }
            Parameter::ClientDisconnected(session, _reason) => {
                self.state.sessions.remove(&*session.id().client_id);
                (true, acc)
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
        if matches!(
            acc,
            Some(HookResult::AuthResult(AuthResult::BadUsernameOrPassword))
                | Some(HookResult::AuthResult(AuthResult::NotAuthorized))
        ) {
            return (false, acc);
        }

        let token = match connect_info.password() {
            Some(pw) => match std::str::from_utf8(pw) {
                Ok(s) => s.to_owned(),
                Err(_) => return deny(),
            },
            None => return deny(),
        };

        let claims = match self.state.jwt_keys.verify(&token) {
            Ok(c)  => c,
            Err(_) => return deny(),
        };

        match crate::db::get_user(&self.state.db, &claims.sub).await {
            Ok(user) if !user.suspended => {}
            _ => return deny(),
        }

        self.state.sessions.insert(connect_info.client_id().to_string(), claims);

        (false, Some(HookResult::AuthResult(AuthResult::Allow(false, None))))
    }

    async fn check_subscribe_acl(
        &self,
        session: &Session,
        subscribe: &Subscribe,
        acc: Option<HookResult>,
    ) -> ReturnType {
        let client_id = &*session.id().client_id;
        let allowed = self.state.sessions
            .get(client_id)
            .map(|claims| claims.sub_topics.iter().any(|t| t.as_str() == &*subscribe.topic_filter))
            .unwrap_or(false);

        if allowed {
            (true, Some(HookResult::SubscribeAclResult(
                rmqtt::types::SubscribeAclResult::new_success(subscribe.opts.qos(), None)
            )))
        } else {
            tracing::debug!(
                "subscribe denied: client={client_id} topic={}",
                subscribe.topic_filter
            );
            (false, Some(HookResult::SubscribeAclResult(
                rmqtt::types::SubscribeAclResult::new_failure(SubscribeAckReason::NotAuthorized)
            )))
        }
    }
}

fn deny() -> ReturnType {
    (false, Some(HookResult::AuthResult(AuthResult::NotAuthorized)))
}
