use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

const DEFAULT_BIND_PATH: &str = "data/telegram.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramBindState {
    pub chat_id: Option<i64>,
    pub blocked_chat_ids: HashSet<i64>,
    pub failed_attempts: HashMap<i64, u32>,
}

pub fn bind_path() -> PathBuf {
    if let Ok(value) = std::env::var("OCI_TELEGRAM_BIND_PATH") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    PathBuf::from(DEFAULT_BIND_PATH)
}

pub fn load_state() -> TelegramBindState {
    let path = bind_path();
    let raw = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return TelegramBindState::default(),
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_state(state: &TelegramBindState) -> Result<()> {
    let path = bind_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(path, raw)?;
    Ok(())
}

pub fn load_chat_id() -> Option<i64> {
    load_state().chat_id
}

pub fn set_chat_id(state: &mut TelegramBindState, chat_id: i64) -> Result<()> {
    state.chat_id = Some(chat_id);
    state.failed_attempts.remove(&chat_id);
    save_state(state)
}

pub fn is_blocked(state: &TelegramBindState, chat_id: i64) -> bool {
    state.blocked_chat_ids.contains(&chat_id)
}

pub fn record_failure(state: &mut TelegramBindState, chat_id: i64) -> Result<(u32, bool)> {
    let count = {
        let entry = state.failed_attempts.entry(chat_id).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    let blocked = count >= 3;
    if blocked {
        state.blocked_chat_ids.insert(chat_id);
    }
    save_state(state)?;
    Ok((count, blocked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn save_and_load_state() {
        let _guard = test_lock().lock().unwrap();
        let temp_dir = std::env::temp_dir().join("oci_manager_bind_test");
        let _ = fs::create_dir_all(&temp_dir);
        let path = temp_dir.join("telegram.json");
        std::env::set_var("OCI_TELEGRAM_BIND_PATH", path.to_string_lossy().to_string());

        let state = TelegramBindState {
            chat_id: Some(4242),
            ..Default::default()
        };
        save_state(&state).expect("save");
        let loaded = load_state();
        assert_eq!(loaded.chat_id, Some(4242));
    }

    #[test]
    fn record_failure_blocks_after_three() {
        let _guard = test_lock().lock().unwrap();
        let temp_dir = std::env::temp_dir().join("oci_manager_bind_test_block");
        let _ = fs::create_dir_all(&temp_dir);
        let path = temp_dir.join("telegram.json");
        std::env::set_var("OCI_TELEGRAM_BIND_PATH", path.to_string_lossy().to_string());

        let mut state = TelegramBindState::default();
        let mut blocked = false;
        for _ in 0..3 {
            let (count, is_blocked) = record_failure(&mut state, 7).expect("failure");
            blocked = is_blocked;
            assert!(count <= 3);
        }
        assert!(blocked);
        assert!(state.blocked_chat_ids.contains(&7));
    }
}
