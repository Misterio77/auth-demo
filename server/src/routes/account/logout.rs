use crate::{database::Database, schema::Session};

use rocket::{
    form::{Form, FromForm},
    get,
    http::{Cookie, CookieJar},
    post,
    request::FlashMessage,
    response::{Flash, Redirect},
    routes, Route,
};
use rocket_db_pools::Connection;
use rocket_dyn_templates::{context, Template};
use serde::Deserialize;

#[get("/")]
fn get(flash: Option<FlashMessage<'_>>, session: Session) -> Result<Template, Flash<Redirect>> {
    Ok(Template::render("logout", context! {flash, session}))
}

#[derive(FromForm, Deserialize)]
struct LogoutForm {
    all: bool,
}

#[post("/", data = "<form>", rank = 1)]
async fn post(
    db: Connection<Database>,
    form: Form<LogoutForm>,
    cookies: &CookieJar<'_>,
    session: Session,
) -> Result<Redirect, Flash<Redirect>> {
    if form.all {
        session.revoke_all(&db).await
    } else {
        session.revoke_self(&db).await
    }
    .map_err(|e| e.flash_redirect("/logout"))?;

    cookies.remove_private(Cookie::from("session"));

    Ok(Redirect::to("/"))
}

pub fn routes() -> Vec<Route> {
    routes![get, post]
}
