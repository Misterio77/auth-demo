use crate::{
    database::{Client, Row},
    error::{ServerError, Status},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub creator: String,
    pub source: IpAddr,
    pub creation: DateTime<Utc>,
}

impl Session {
    async fn get(db: &Client, id: Uuid) -> Result<Session, ServerError> {
        db.query_one(
            "SELECT id, creator, source, creation
            FROM sessions
            WHERE id = $1",
            &[&id],
        )
        .await?
        .try_into()
    }
    async fn list(db: &Client, creator: &str) -> Result<Vec<Session>, ServerError> {
        db.query(
            "SELECT id, creator, source, creation
            FROM sessions
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
            "DELETE FROM sessions
            WHERE creator = $1 AND ($2::uuid IS NULL OR id = $2)",
            &[&creator, &id],
        )
        .await?;
        Ok(())
    }
    async fn insert(&self, db: &Client) -> Result<(), ServerError> {
        db.execute(
            "INSERT INTO sessions
            (id, creator, source, creation)
            VALUES ($1, $2, $3, $4)",
            &[&self.id, &self.creator, &self.source, &self.creation],
        )
        .await?;
        Ok(())
    }

    pub async fn create(db: &Client, username: &str, ip: IpAddr) -> Result<Session, ServerError> {
        let session = Session {
            id: Uuid::new_v4(),
            creator: username.into(),
            source: ip,
            creation: Utc::now(),
        };
        session.insert(db).await?;
        Ok(session)
    }
    pub async fn authenticate(db: &Client, id: Uuid) -> Result<Session, ServerError> {
        Session::get(db, id).await.map_err(|e| {
            ServerError::builder_from(e)
                .code(Status::Unauthorized)
                .message("Session expired, please login again")
                .into()
        })
    }
    pub async fn show_all(&self, db: &Client) -> Result<Vec<Session>, ServerError> {
        Session::list(db, &self.creator).await
    }
    pub async fn revoke(&self, db: &Client, id: Option<Uuid>) -> Result<(), ServerError> {
        Session::delete(db, &self.creator, id).await?;
        Ok(())
    }
    pub async fn revoke_self(self, db: &Client) -> Result<(), ServerError> {
        self.revoke(db, Some(self.id)).await?;
        Ok(())
    }
    pub async fn revoke_all(self, db: &Client) -> Result<(), ServerError> {
        self.revoke(db, None).await?;
        Ok(())
    }
}

impl TryFrom<Row> for Session {
    type Error = ServerError;
    fn try_from(row: Row) -> Result<Session, ServerError> {
        Ok(Session {
            id: row.try_get("id")?,
            creator: row.try_get("creator")?,
            source: row.try_get("source")?,
            creation: row.try_get("creation")?,
        })
    }
}

use rocket::http::Cookie;
impl From<Session> for Cookie<'_> {
    fn from(session: Session) -> Self {
        Cookie::build(("session", session.id.to_string()))
            .permanent()
            .into()
    }
}

use crate::database::Database;
use rocket::{
    outcome::{try_outcome, IntoOutcome},
    request::{self, FromRequest, Request},
};
use rocket_db_pools::Connection;
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Session {
    type Error = ServerError;
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let cookies = request.cookies();

        let db = try_outcome!(request
            .guard::<Connection<Database>>()
            .await
            .map_error(ServerError::from));

        let id = try_outcome!(cookies
            .get_private("session")
            .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
            .or_error(
                ServerError::builder()
                    .code(Status::Unauthorized)
                    .message("You're not logged in")
                    .build()
            ));

        let session = try_outcome!(Session::authenticate(&db, id)
            .await
            .or_error(Status::Unauthorized));

        request::Outcome::Success(session)
    }
}
