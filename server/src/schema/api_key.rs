use crate::{
    database::{Client, Row},
    error::{ServerError, Status},
    schema::Session,
};

use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: Option<String>,
    pub creator: String,
    pub creation: DateTime<Utc>,
    #[serde(skip_serializing)]
    key: String,
}

impl ApiKey {
    async fn get(db: &Client, key: &str) -> Result<ApiKey, ServerError> {
        db.query_one(
            "SELECT id, name, creator, creation, key
            FROM api_keys
            WHERE key = $1",
            &[&key],
        )
        .await?
        .try_into()
    }
    async fn list(db: &Client, creator: &str) -> Result<Vec<ApiKey>, ServerError> {
        db.query(
            "SELECT id, name, creator, creation, key
            FROM api_keys
            WHERE creator = $1",
            &[&creator],
        )
        .await?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }
    async fn delete(db: &Client, creator: &str, id: Option<Uuid>) -> Result<(), ServerError> {
        db.execute(
            "DELETE FROM api_keys
            WHERE creator = $1 AND ($2::uuid IS NULL OR id = $2)",
            &[&creator, &id],
        )
        .await?;
        Ok(())
    }
    async fn insert(&self, db: &Client) -> Result<(), ServerError> {
        db.execute(
            "INSERT INTO api_keys
            (id, name, creator, creation, key)
            VALUES ($1, $2, $3, $4, $5)",
            &[
                &self.id,
                &self.name,
                &self.creator,
                &self.creation,
                &self.key,
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn create(
        db: &Client,
        session: &Session,
        name: Option<String>,
    ) -> Result<String, ServerError> {
        let generated_key: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let key = ApiKey {
            id: Uuid::new_v4(),
            name: name.filter(|s| !s.is_empty()),
            creator: session.creator.clone(),
            creation: Utc::now(),
            key: generated_key.clone(),
        };
        key.insert(db).await?;
        Ok(generated_key)
    }
    pub async fn authenticate(db: &Client, key: String) -> Result<ApiKey, ServerError> {
        ApiKey::get(db, &key).await.map_err(|e| {
            ServerError::builder_from(e)
                .code(Status::Unauthorized)
                .message("API key expired, please generate another")
                .into()
        })
    }
    pub async fn show_all(db: &Client, session: &Session) -> Result<Vec<ApiKey>, ServerError> {
        ApiKey::list(db, &session.creator).await
    }
    pub async fn revoke(
        db: &Client,
        session: &Session,
        id: Option<Uuid>,
    ) -> Result<(), ServerError> {
        ApiKey::delete(db, &session.creator, id).await?;
        Ok(())
    }
}

impl TryFrom<Row> for ApiKey {
    type Error = ServerError;
    fn try_from(row: Row) -> Result<ApiKey, ServerError> {
        Ok(ApiKey {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            creator: row.try_get("creator")?,
            creation: row.try_get("creation")?,
            key: row.try_get("key")?,
        })
    }
}

use crate::database::Database;
use rocket::{
    outcome::{try_outcome, IntoOutcome},
    request::{self, FromRequest, Request},
};
use rocket_db_pools::Connection;
#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey {
    type Error = ServerError;
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let db = try_outcome!(request
            .guard::<Connection<Database>>()
            .await
            .map_error(ServerError::from));

        let key = try_outcome!(request
            .headers()
            .get("Authorization")
            .next()
            .and_then(|h| h.split_whitespace().last().map(|k| k.to_string()))
            .or_error(
                ServerError::builder()
                    .code(Status::Unauthorized)
                    .message("You must supply an API Key")
                    .build()
            ));

        let session = try_outcome!(ApiKey::authenticate(&db, key)
            .await
            .or_error(Status::Unauthorized));

        request::Outcome::Success(session)
    }
}
