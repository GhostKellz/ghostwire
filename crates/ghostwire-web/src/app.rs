/// Main application component and routing
///
/// Defines the root App component with routing, authentication, and global state management.

use leptos::*;
use leptos_meta::*;
use leptos_router::*;

use crate::auth::{AuthProvider, use_auth};
use crate::components::shell::Shell;
use crate::components::notifications::NotificationProvider;
use crate::pages::{
    auth::{LoginPage, LogoutPage},
    dashboard::DashboardPage,
    machines::MachinesPage,
    users::UsersPage,
    dns::DnsPage,
    policies::PoliciesPage,
    settings::SettingsPage,
    not_found::NotFoundPage,
};

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/ghostwire-web.css"/>
        <Title text="GhostWire Admin"/>
        <Meta name="description" content="GhostWire mesh VPN administration interface"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1.0"/>

        <Router>
            <AuthProvider>
                <NotificationProvider>
                    <Routes>
                        // Public routes
                        <Route path="/auth/login" view=LoginPage/>
                        <Route path="/auth/logout" view=LogoutPage/>

                        // Protected routes wrapped in Shell
                        <ProtectedRoute
                            path="/*any"
                            view=move || view! {
                                <Shell>
                                    <Routes>
                                        <Route path="/" view=DashboardPage/>
                                        <Route path="/dashboard" view=DashboardPage/>
                                        <Route path="/machines" view=MachinesPage/>
                                        <Route path="/users" view=UsersPage/>
                                        <Route path="/dns" view=DnsPage/>
                                        <Route path="/policies" view=PoliciesPage/>
                                        <Route path="/settings/*any" view=SettingsPage/>
                                        <Route path="/*any" view=NotFoundPage/>
                                    </Routes>
                                </Shell>
                            }
                        />
                    </Routes>
                </NotificationProvider>
            </AuthProvider>
        </Router>
    }
}

/// Protected route component that checks authentication
#[component]
fn ProtectedRoute<F, IV>(
    /// The route path
    path: &'static str,
    /// The view component to render if authenticated
    view: F,
) -> impl IntoView
where
    F: Fn() -> IV + 'static,
    IV: IntoView + 'static,
{
    let auth = use_auth();

    view! {
        <Route
            path=path
            view=move || {
                match auth.session.get() {
                    Some(_) => view().into_view(),
                    None => {
                        // Redirect to login if not authenticated
                        let navigate = use_navigate();
                        create_effect(move |_| {
                            navigate("/auth/login", Default::default());
                        });
                        view! { <div>"Redirecting to login..."</div> }.into_view()
                    }
                }
            }
        />
    }
}