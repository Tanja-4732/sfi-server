//! This file manages the event-sourcing activities related to the server-side logic

use super::types::User;
use anyhow::Result;
use libocc::{Event, Projector};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EventSourcingService {
    projector: Projector<User>,
}

impl EventSourcingService {
    pub fn new() -> Self {
        Self {
            projector: Projector::new(),
        }
    }

    pub fn load(projector: Projector<User>) -> Self {
        Self { projector }
    }

    pub fn borrow(&self) -> &Projector<User> {
        &self.projector
    }

    pub fn borrow_mut(&mut self) -> &mut Projector<User> {
        &mut self.projector
    }
}
