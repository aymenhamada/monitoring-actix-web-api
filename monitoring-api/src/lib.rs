use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

use actix_web::{
    body::EitherBody,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};

pub struct Authentification;

impl<S, B> Transform<S, ServiceRequest> for Authentification
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthentificationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthentificationMiddleware { service }))
    }
}
pub struct AuthentificationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthentificationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        if request.path().contains("/metrics") {
            let mut is_authed = false;
            if let Some(authen_bearer) = request.headers().get("Authorization") {
                if let Ok(authen_str) = authen_bearer.to_str() {
                    let token = authen_str[6..authen_str.len()].trim();
                    is_authed = token == "bearer_token";
                }
            }

            if !is_authed {
                let (request, _pl) = request.into_parts();

                let response = HttpResponse::Unauthorized()
                    .body("Only prometheus can use me !")
                    .map_into_right_body();

                return Box::pin(async { Ok(ServiceResponse::new(request, response)) });
            }
        }
        let res = self.service.call(request);

        Box::pin(async move { res.await.map(ServiceResponse::map_into_left_body) })
    }
}
