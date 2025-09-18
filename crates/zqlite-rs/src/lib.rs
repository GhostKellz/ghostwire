pub mod error;
pub mod connection;
pub mod pool;
pub mod async_connection;
pub mod metrics;
pub mod types;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;
use parking_lot::RwLock;

pub use connection::Connection;
pub use pool::{Pool, PoolConfig};
pub use async_connection::AsyncConnection;
pub use error::{Error, Result};
pub use types::*;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;

pub struct ZQLite {
    inner: Arc<RwLock<ZQLiteInner>>,
}

struct ZQLiteInner {
    db: *mut c_void,
    path: String,
}

unsafe impl Send for ZQLiteInner {}
unsafe impl Sync for ZQLiteInner {}

impl ZQLite {
    pub fn new() -> Result<Self> {
        Self::open(":memory:")
    }

    pub fn open(path: &str) -> Result<Self> {
        let c_path = CString::new(path)?;
        let mut db: *mut c_void = ptr::null_mut();

        let result = unsafe {
            bindings::zqlite_open(
                c_path.as_ptr(),
                &mut db as *mut *mut c_void,
            )
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to open database: code {}",
                result
            )));
        }

        Ok(ZQLite {
            inner: Arc::new(RwLock::new(ZQLiteInner {
                db,
                path: path.to_string(),
            })),
        })
    }

    pub fn execute(&self, sql: &str) -> Result<()> {
        let c_sql = CString::new(sql)?;
        let inner = self.inner.read();

        let result = unsafe {
            bindings::zqlite_exec(
                inner.db,
                c_sql.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to execute SQL: code {}",
                result
            )));
        }

        Ok(())
    }

    pub fn prepare(&self, sql: &str) -> Result<Statement> {
        let c_sql = CString::new(sql)?;
        let mut stmt: *mut c_void = ptr::null_mut();
        let inner = self.inner.read();

        let result = unsafe {
            bindings::zqlite_prepare(
                inner.db,
                c_sql.as_ptr(),
                -1,
                &mut stmt as *mut *mut c_void,
                ptr::null_mut(),
            )
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to prepare statement: code {}",
                result
            )));
        }

        Ok(Statement {
            stmt,
            db: self.inner.clone(),
        })
    }

    pub fn last_insert_rowid(&self) -> i64 {
        let inner = self.inner.read();
        unsafe { bindings::zqlite_last_insert_rowid(inner.db) }
    }

    pub fn changes(&self) -> i32 {
        let inner = self.inner.read();
        unsafe { bindings::zqlite_changes(inner.db) }
    }

    pub fn enable_post_quantum(&self) -> Result<()> {
        let inner = self.inner.read();
        let result = unsafe {
            bindings::zqlite_enable_post_quantum(inner.db)
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to enable post-quantum crypto: code {}",
                result
            )));
        }

        Ok(())
    }
}

impl Drop for ZQLiteInner {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe {
                bindings::zqlite_close(self.db);
            }
        }
    }
}

pub struct Statement {
    stmt: *mut c_void,
    db: Arc<RwLock<ZQLiteInner>>,
}

unsafe impl Send for Statement {}
unsafe impl Sync for Statement {}

impl Statement {
    pub fn bind_text(&mut self, index: i32, value: &str) -> Result<()> {
        let c_value = CString::new(value)?;
        let result = unsafe {
            bindings::zqlite_bind_text(
                self.stmt,
                index,
                c_value.as_ptr(),
                value.len() as i32,
                None,
            )
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to bind text: code {}",
                result
            )));
        }

        Ok(())
    }

    pub fn bind_int(&mut self, index: i32, value: i32) -> Result<()> {
        let result = unsafe {
            bindings::zqlite_bind_int(self.stmt, index, value)
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to bind int: code {}",
                result
            )));
        }

        Ok(())
    }

    pub fn bind_int64(&mut self, index: i32, value: i64) -> Result<()> {
        let result = unsafe {
            bindings::zqlite_bind_int64(self.stmt, index, value)
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to bind int64: code {}",
                result
            )));
        }

        Ok(())
    }

    pub fn bind_blob(&mut self, index: i32, value: &[u8]) -> Result<()> {
        let result = unsafe {
            bindings::zqlite_bind_blob(
                self.stmt,
                index,
                value.as_ptr() as *const c_void,
                value.len() as i32,
                None,
            )
        };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to bind blob: code {}",
                result
            )));
        }

        Ok(())
    }

    pub fn step(&mut self) -> Result<bool> {
        let result = unsafe { bindings::zqlite_step(self.stmt) };

        match result {
            100 => Ok(true),  // SQLITE_ROW
            101 => Ok(false), // SQLITE_DONE
            _ => Err(Error::Database(format!(
                "Failed to step statement: code {}",
                result
            ))),
        }
    }

    pub fn column_text(&self, index: i32) -> Result<String> {
        let text_ptr = unsafe {
            bindings::zqlite_column_text(self.stmt, index)
        };

        if text_ptr.is_null() {
            return Ok(String::new());
        }

        let c_str = unsafe { CStr::from_ptr(text_ptr as *const c_char) };
        Ok(c_str.to_string_lossy().into_owned())
    }

    pub fn column_int(&self, index: i32) -> i32 {
        unsafe { bindings::zqlite_column_int(self.stmt, index) }
    }

    pub fn column_int64(&self, index: i32) -> i64 {
        unsafe { bindings::zqlite_column_int64(self.stmt, index) }
    }

    pub fn column_blob(&self, index: i32) -> Vec<u8> {
        let blob_ptr = unsafe {
            bindings::zqlite_column_blob(self.stmt, index)
        };

        if blob_ptr.is_null() {
            return Vec::new();
        }

        let size = unsafe {
            bindings::zqlite_column_bytes(self.stmt, index)
        };

        let slice = unsafe {
            std::slice::from_raw_parts(blob_ptr as *const u8, size as usize)
        };

        slice.to_vec()
    }

    pub fn reset(&mut self) -> Result<()> {
        let result = unsafe { bindings::zqlite_reset(self.stmt) };

        if result != 0 {
            return Err(Error::Database(format!(
                "Failed to reset statement: code {}",
                result
            )));
        }

        Ok(())
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.stmt.is_null() {
            unsafe {
                bindings::zqlite_finalize(self.stmt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let db = ZQLite::new().unwrap();
        db.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
            .unwrap();
    }

    #[test]
    fn test_insert_select() {
        let db = ZQLite::new().unwrap();
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
            .unwrap();

        let mut stmt = db.prepare("INSERT INTO users (name) VALUES (?)").unwrap();
        stmt.bind_text(1, "Alice").unwrap();
        stmt.step().unwrap();

        let mut query = db.prepare("SELECT name FROM users WHERE id = ?").unwrap();
        query.bind_int(1, 1).unwrap();

        assert!(query.step().unwrap());
        assert_eq!(query.column_text(0).unwrap(), "Alice");
        assert!(!query.step().unwrap());
    }
}