pub mod auth_service;
pub mod chat_service;
pub mod e2ee_service;
pub mod health_service;
pub mod realtime_service;
pub mod user_service;

use crate::state::AppState;

#[derive(Clone)]
pub struct ServiceFactory {
	state: AppState,
}

impl ServiceFactory {
	pub fn new(state: AppState) -> Self {
		Self { state }
	}

	pub fn auth(&self) -> auth_service::AuthService {
		auth_service::AuthService::new(self.state.clone())
	}

	pub fn user(&self) -> user_service::UserService {
		user_service::UserService::new(self.state.clone())
	}

	pub fn chat(&self) -> chat_service::ChatService {
		chat_service::ChatService::new(self.state.clone())
	}

	pub fn e2ee(&self) -> e2ee_service::E2eeService {
		e2ee_service::E2eeService::new(self.state.clone())
	}

	pub fn health(&self) -> health_service::HealthService {
		health_service::HealthService::new(self.state.clone())
	}

	pub fn realtime(&self) -> realtime_service::RealtimeService {
		realtime_service::RealtimeService::new(self.state.clone())
	}
}
