use crate::{Error, Result, Value, QueryResult, ZQLite, Statement};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub struct Connection {
    db: Arc<ZQLite>,
    id: u64,
    transaction_depth: Arc<RwLock<u32>>,
}

impl Connection {
    pub fn new(db: ZQLite) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Self {
            db: Arc::new(db),
            id,
            transaction_depth: Arc::new(RwLock::new(0)),
        }
    }

    pub fn open(path: &str) -> Result<Self> {
        let db = ZQLite::open(path)?;
        Ok(Self::new(db))
    }

    pub fn execute(&self, sql: &str) -> Result<QueryResult> {
        self.execute_with_params(sql, &[])
    }

    pub fn execute_with_params(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        trace!(connection_id = self.id, sql = %sql, param_count = params.len(), "Executing SQL");

        let mut stmt = self.db.prepare(sql)?;

        for (i, param) in params.iter().enumerate() {
            match param {
                Value::Null => {
                    // SQLite handles NULL binding automatically
                }
                Value::Integer(i) => stmt.bind_int64((i + 1) as i32, *i)?,
                Value::Real(f) => {
                    // ZQLite doesn't have bind_double in our FFI, convert to text
                    stmt.bind_text((i + 1) as i32, &f.to_string())?;
                }
                Value::Text(s) => stmt.bind_text((i + 1) as i32, s)?,
                Value::Blob(b) => stmt.bind_blob((i + 1) as i32, b)?,
            }
        }

        let mut result = QueryResult::new();
        let mut first_row = true;

        while stmt.step()? {
            if first_row {
                // Get column names (this is a simplified approach)
                let column_count = self.get_column_count(&stmt)?;
                for i in 0..column_count {
                    result.columns.push(format!("column_{}", i));
                }
                first_row = false;
            }

            let mut row = Vec::new();
            for i in 0..result.columns.len() {
                let value = self.get_column_value(&stmt, i as i32)?;
                row.push(value);
            }
            result.add_row(row);
        }

        result.affected_rows = self.db.changes() as u64;
        if result.affected_rows > 0 {
            result.last_insert_id = Some(self.db.last_insert_rowid());
        }

        debug!(
            connection_id = self.id,
            rows_returned = result.len(),
            affected_rows = result.affected_rows,
            "Query completed"
        );

        Ok(result)
    }

    fn get_column_count(&self, _stmt: &Statement) -> Result<usize> {
        // This is a simplified implementation
        // In a real implementation, you'd use zqlite_column_count
        Ok(1)
    }

    fn get_column_value(&self, stmt: &Statement, index: i32) -> Result<Value> {
        // This is a simplified implementation
        // In practice, you'd need to check the column type first
        match stmt.column_text(index) {
            Ok(text) => {
                if text.is_empty() {
                    Ok(Value::Null)
                } else {
                    Ok(Value::Text(text))
                }
            }
            Err(_) => {
                let int_val = stmt.column_int64(index);
                Ok(Value::Integer(int_val))
            }
        }
    }

    pub fn begin_transaction(&self) -> Result<Transaction> {
        let mut depth = self.transaction_depth.write();
        if *depth == 0 {
            self.db.execute("BEGIN")?;
            debug!(connection_id = self.id, "Transaction started");
        }
        *depth += 1;

        Ok(Transaction {
            connection: self.clone(),
            committed: false,
        })
    }

    fn commit_transaction(&self) -> Result<()> {
        let mut depth = self.transaction_depth.write();
        if *depth == 0 {
            return Err(Error::Transaction("No active transaction".to_string()));
        }

        *depth -= 1;
        if *depth == 0 {
            self.db.execute("COMMIT")?;
            debug!(connection_id = self.id, "Transaction committed");
        }

        Ok(())
    }

    fn rollback_transaction(&self) -> Result<()> {
        let mut depth = self.transaction_depth.write();
        if *depth == 0 {
            return Err(Error::Transaction("No active transaction".to_string()));
        }

        *depth = 0;
        self.db.execute("ROLLBACK")?;
        warn!(connection_id = self.id, "Transaction rolled back");

        Ok(())
    }

    pub fn ping(&self) -> Result<()> {
        self.execute("SELECT 1")?;
        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn enable_post_quantum(&self) -> Result<()> {
        self.db.enable_post_quantum()
    }
}

pub struct Transaction {
    connection: Connection,
    committed: bool,
}

impl Transaction {
    pub fn execute(&self, sql: &str) -> Result<QueryResult> {
        self.connection.execute(sql)
    }

    pub fn execute_with_params(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.connection.execute_with_params(sql, params)
    }

    pub fn commit(mut self) -> Result<()> {
        self.connection.commit_transaction()?;
        self.committed = true;
        Ok(())
    }

    pub fn rollback(mut self) -> Result<()> {
        self.connection.rollback_transaction()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(e) = self.connection.rollback_transaction() {
                warn!(error = %e, "Failed to rollback transaction on drop");
            }
        }
    }
}