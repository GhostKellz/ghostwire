use crate::{Connection, Error, Result, Value, QueryResult, Pool, PoolConfig};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task;
use tracing::{debug, trace};

#[async_trait]
pub trait AsyncDatabase: Send + Sync {
    async fn execute(&self, sql: &str) -> Result<QueryResult>;
    async fn execute_with_params(&self, sql: &str, params: &[Value]) -> Result<QueryResult>;
    async fn begin_transaction(&self) -> Result<AsyncTransaction>;
    async fn ping(&self) -> Result<()>;
}

pub struct AsyncConnection {
    inner: ConnectionInner,
}

enum ConnectionInner {
    Direct(Arc<Connection>),
    Pooled(Arc<Pool>),
}

impl AsyncConnection {
    pub fn new(connection: Connection) -> Self {
        Self {
            inner: ConnectionInner::Direct(Arc::new(connection)),
        }
    }

    pub async fn open(path: &str) -> Result<Self> {
        let connection = task::spawn_blocking({
            let path = path.to_string();
            move || Connection::open(&path)
        })
        .await
        .map_err(|e| Error::Other(format!("Task join error: {}", e)))??;

        Ok(Self::new(connection))
    }

    pub async fn with_pool(config: PoolConfig) -> Result<Self> {
        let pool = Pool::new(config).await?;
        Ok(Self {
            inner: ConnectionInner::Pooled(Arc::new(pool)),
        })
    }

    async fn with_connection<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        match &self.inner {
            ConnectionInner::Direct(conn) => {
                let conn = conn.clone();
                task::spawn_blocking(move || f(&conn))
                    .await
                    .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
            }
            ConnectionInner::Pooled(pool) => {
                let guard = pool.get().await?;
                let conn = guard.connection().clone();
                task::spawn_blocking(move || f(&conn))
                    .await
                    .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
            }
        }
    }
}

#[async_trait]
impl AsyncDatabase for AsyncConnection {
    async fn execute(&self, sql: &str) -> Result<QueryResult> {
        trace!(sql = %sql, "Executing async SQL");

        self.with_connection({
            let sql = sql.to_string();
            move |conn| conn.execute(&sql)
        })
        .await
    }

    async fn execute_with_params(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        trace!(sql = %sql, param_count = params.len(), "Executing async SQL with params");

        self.with_connection({
            let sql = sql.to_string();
            let params = params.to_vec();
            move |conn| conn.execute_with_params(&sql, &params)
        })
        .await
    }

    async fn begin_transaction(&self) -> Result<AsyncTransaction> {
        let tx = self.with_connection(|conn| conn.begin_transaction()).await?;
        Ok(AsyncTransaction::new(tx))
    }

    async fn ping(&self) -> Result<()> {
        self.with_connection(|conn| conn.ping()).await
    }
}

pub struct AsyncTransaction {
    inner: Option<crate::connection::Transaction>,
}

impl AsyncTransaction {
    fn new(transaction: crate::connection::Transaction) -> Self {
        Self {
            inner: Some(transaction),
        }
    }

    pub async fn execute(&self, sql: &str) -> Result<QueryResult> {
        if let Some(ref tx) = self.inner {
            let tx = tx.clone(); // Assuming Transaction implements Clone
            let sql = sql.to_string();

            task::spawn_blocking(move || tx.execute(&sql))
                .await
                .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
        } else {
            Err(Error::Transaction("Transaction already consumed".to_string()))
        }
    }

    pub async fn execute_with_params(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        if let Some(ref tx) = self.inner {
            let tx = tx.clone();
            let sql = sql.to_string();
            let params = params.to_vec();

            task::spawn_blocking(move || tx.execute_with_params(&sql, &params))
                .await
                .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
        } else {
            Err(Error::Transaction("Transaction already consumed".to_string()))
        }
    }

    pub async fn commit(mut self) -> Result<()> {
        if let Some(tx) = self.inner.take() {
            task::spawn_blocking(move || tx.commit())
                .await
                .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
        } else {
            Err(Error::Transaction("Transaction already consumed".to_string()))
        }
    }

    pub async fn rollback(mut self) -> Result<()> {
        if let Some(tx) = self.inner.take() {
            task::spawn_blocking(move || tx.rollback())
                .await
                .map_err(|e| Error::Other(format!("Task join error: {}", e)))?
        } else {
            Err(Error::Transaction("Transaction already consumed".to_string()))
        }
    }
}

// Batch operations for high-performance scenarios
impl AsyncConnection {
    pub async fn execute_batch(&self, statements: Vec<(String, Vec<Value>)>) -> Result<Vec<QueryResult>> {
        self.with_connection(move |conn| {
            let mut results = Vec::new();
            for (sql, params) in statements {
                let result = conn.execute_with_params(&sql, &params)?;
                results.push(result);
            }
            Ok(results)
        })
        .await
    }

    pub async fn execute_batch_in_transaction(
        &self,
        statements: Vec<(String, Vec<Value>)>,
    ) -> Result<Vec<QueryResult>> {
        let tx = self.begin_transaction().await?;
        let mut results = Vec::new();

        for (sql, params) in statements {
            match tx.execute_with_params(&sql, &params).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    tx.rollback().await?;
                    return Err(e);
                }
            }
        }

        tx.commit().await?;
        Ok(results)
    }

    pub async fn enable_post_quantum(&self) -> Result<()> {
        self.with_connection(|conn| conn.enable_post_quantum()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_connection() {
        let conn = AsyncConnection::open(":memory:").await.unwrap();

        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        let result = conn
            .execute_with_params(
                "INSERT INTO test (name) VALUES (?)",
                &[Value::Text("Alice".to_string())],
            )
            .await
            .unwrap();

        assert_eq!(result.affected_rows, 1);
        assert!(result.last_insert_id.is_some());
    }

    #[tokio::test]
    async fn test_async_transaction() {
        let conn = AsyncConnection::open(":memory:").await.unwrap();

        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        let tx = conn.begin_transaction().await.unwrap();

        tx.execute_with_params(
            "INSERT INTO test (name) VALUES (?)",
            &[Value::Text("Bob".to_string())],
        )
        .await
        .unwrap();

        tx.commit().await.unwrap();

        let result = conn.execute("SELECT COUNT(*) FROM test").await.unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_pooled_connection() {
        let config = PoolConfig {
            min_connections: 2,
            max_connections: 5,
            database_path: ":memory:".to_string(),
            ..Default::default()
        };

        let conn = AsyncConnection::with_pool(config).await.unwrap();

        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        // Test concurrent operations
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let conn = conn.clone();
                tokio::spawn(async move {
                    conn.execute_with_params(
                        "INSERT INTO test (name) VALUES (?)",
                        &[Value::Text(format!("User {}", i))],
                    )
                    .await
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        let result = conn.execute("SELECT COUNT(*) FROM test").await.unwrap();
        assert_eq!(result.len(), 1);
    }
}

impl Clone for AsyncConnection {
    fn clone(&self) -> Self {
        Self {
            inner: match &self.inner {
                ConnectionInner::Direct(conn) => ConnectionInner::Direct(conn.clone()),
                ConnectionInner::Pooled(pool) => ConnectionInner::Pooled(pool.clone()),
            },
        }
    }
}