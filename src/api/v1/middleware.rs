use super::authentication::extract_uuid_from_jwt;
use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error};
use actix_web::{HttpMessage, HttpResponse};
use anyhow::Result;
use futures::{
    future::{ok, Either, Ready},
    Future,
};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct AuthUser;

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S> for AuthUser
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthUserMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthUserMiddleware { service })
    }
}

pub struct AuthUserMiddleware<S> {
    service: S,
}

impl<S, B> Service for AuthUserMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        // We only need to hook into the `start` for this middleware.

        // Get the JWT cookie (if any)
        let res = if let Some(jwt_cookie) = req.cookie("jwt") {
            // Validate the JWT
            if let Ok(uuid) = extract_uuid_from_jwt(jwt_cookie.value()) {
                // Insert the UUID into the request
                req.extensions_mut().deref_mut().insert(uuid);

                // Keep processing the request
                Either::Left(self.service.call(req))
            } else {
                // Invalid JWT

                // TODO return custom body
                // HttpResponse::Unauthorized().finish().body(json!({
                //     "error": "Invalid credentials"
                // }))

                // Return unauthorized
                Either::Right(ok(
                    req.into_response(HttpResponse::Unauthorized().finish().into_body())
                ))
            }
        } else {
            // No JWT present

            // TODO return custom body
            // HttpResponse::Unauthorized().body(json!({
            //     "status": "Not logged in"
            // }))

            // Return unauthorized
            Either::Right(ok(
                req.into_response(HttpResponse::Unauthorized().finish().into_body())
            ))
        };

        Box::pin(res)
    }

    // fn call_a(&mut self, req: ServiceRequest) -> Self::Future {

    //     // Auth start
    //     // Get the JWT cookie (if any)
    //     let res = if let Some(jwt_cookie) = req.cookie("jwt") {
    //         // Validate the JWT
    //         if let Ok(uuid) = extract_uuid_from_jwt(jwt_cookie.value()) {
    //             // Keep processing the request
    //             let res = self.service.call(req);

    //             ok(res)
    //         } else {
    //             // Invalid JWT

    //             HttpResponse::Unauthorized().finish().body(json!({
    //                 "error": "Invalid credentials"
    //             }))
    //         }
    //     } else {
    //         // No JWT present
    //         HttpResponse::Ok().body(json!({
    //             "status": "Not logged in"
    //         }))
    //     };

    //     // Auth end
    //     Box::pin(res)
    // }
}
