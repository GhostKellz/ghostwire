/// Authentication pages (login, logout)
///
/// User authentication interface with login form and logout handling.

use leptos::*;
use leptos_router::*;

use crate::auth::{use_auth, LoginRequest};
use crate::components::icons::*;

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    let (username, set_username) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);

    // Redirect if already authenticated
    create_effect(move |_| {
        if auth.session.get().is_some() {
            navigate("/dashboard", Default::default());
        }
    });

    // Handle form submission
    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let login_request = LoginRequest {
            username: username.get(),
            password: password.get(),
        };

        auth.login.dispatch(login_request);
    };

    // Watch for login result
    create_effect(move |_| {
        if let Some(result) = auth.login.value().get() {
            match result {
                Ok(_) => {
                    navigate("/dashboard", Default::default());
                }
                Err(error) => {
                    set_error_message.set(Some(error));
                }
            }
        }
    });

    view! {
        <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
            <div class="max-w-md w-full space-y-8">
                <div class="text-center">
                    <div class="flex justify-center">
                        <GhostWireLogo class="h-12 w-12 text-blue-600"/>
                    </div>
                    <h2 class="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">
                        "Sign in to GhostWire"
                    </h2>
                    <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                        "Manage your mesh VPN network"
                    </p>
                </div>

                <form class="mt-8 space-y-6" on:submit=handle_submit>
                    <div class="space-y-4">
                        <div>
                            <label for="username" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                "Username"
                            </label>
                            <input
                                id="username"
                                name="username"
                                type="text"
                                required
                                autocomplete="username"
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                placeholder="Enter your username"
                                prop:value=username
                                on:input=move |ev| set_username.set(event_target_value(&ev))
                            />
                        </div>

                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                "Password"
                            </label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                autocomplete="current-password"
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                placeholder="Enter your password"
                                prop:value=password
                                on:input=move |ev| set_password.set(event_target_value(&ev))
                            />
                        </div>
                    </div>

                    <Show when=move || error_message.get().is_some()>
                        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <AlertIcon/>
                                </div>
                                <div class="ml-3">
                                    <h3 class="text-sm font-medium text-red-800 dark:text-red-400">
                                        "Authentication Failed"
                                    </h3>
                                    <div class="mt-2 text-sm text-red-700 dark:text-red-300">
                                        {move || error_message.get().unwrap_or_default()}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Show>

                    <div>
                        <button
                            type="submit"
                            disabled=move || auth.is_loading.get()
                            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                            <Show
                                when=move || auth.is_loading.get()
                                fallback=|| view! { "Sign in" }
                            >
                                <div class="flex items-center space-x-2">
                                    <LoadingIcon/>
                                    <span>"Signing in..."</span>
                                </div>
                            </Show>
                        </button>
                    </div>

                    <div class="text-center">
                        <p class="text-sm text-gray-600 dark:text-gray-400">
                            "Need help? Contact your administrator"
                        </p>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[component]
pub fn LogoutPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    // Trigger logout and redirect
    create_effect(move |_| {
        auth.logout.dispatch(());
        navigate("/auth/login", Default::default());
    });

    view! {
        <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
            <div class="text-center">
                <LoadingIcon/>
                <p class="mt-4 text-gray-600 dark:text-gray-400">
                    "Signing out..."
                </p>
            </div>
        </div>
    }
}