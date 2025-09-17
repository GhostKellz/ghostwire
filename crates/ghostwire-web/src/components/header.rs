/// Header component with navigation and user menu
///
/// Main application header with branding, navigation tabs, and user controls.

use leptos::*;
use leptos_router::*;

use crate::auth::{use_auth, has_permission};
use crate::types::AuthSession;
use crate::components::icons::*;

#[component]
pub fn Header(
    #[prop(into)]
    session: Signal<Option<AuthSession>>,
) -> impl IntoView {
    let auth = use_auth();

    view! {
        <header class="bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 shadow-sm">
            <div class="container mx-auto px-4">
                <div class="flex items-center justify-between h-16">
                    {/* Logo and branding */}
                    <div class="flex items-center space-x-3">
                        <div class="flex items-center space-x-2">
                            <GhostWireLogo class="h-8 w-8 text-blue-600"/>
                            <h1 class="text-xl font-bold text-gray-900 dark:text-white">
                                "GhostWire"
                            </h1>
                        </div>
                    </div>

                    {/* External links */}
                    <div class="hidden md:flex items-center space-x-4">
                        <a
                            href="https://github.com/ghostkellz/ghostwire"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                        >
                            "GitHub"
                        </a>
                        <a
                            href="https://tailscale.com/download"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                        >
                            "Download"
                        </a>

                        {/* User menu */}
                        <Show when=move || session.get().is_some()>
                            <UserMenu session=session />
                        </Show>
                    </div>
                </div>

                {/* Navigation tabs */}
                <Show when=move || {
                    if let Some(s) = session.get() {
                        has_permission(&s, "ui_access")
                    } else {
                        false
                    }
                }>
                    <NavigationTabs session=session />
                </Show>
            </div>
        </header>
    }
}

#[component]
fn NavigationTabs(
    #[prop(into)]
    session: Signal<Option<AuthSession>>,
) -> impl IntoView {
    let location = use_location();

    view! {
        <nav class="flex space-x-1 pb-0 overflow-x-auto">
            <Show when=move || {
                if let Some(s) = session.get() {
                    has_permission(&s, "read_machines")
                } else {
                    false
                }
            }>
                <NavTab
                    href="/machines"
                    icon=ServerIcon
                    label="Machines"
                    active=move || location.pathname.get().starts_with("/machines")
                />
            </Show>

            <Show when=move || {
                if let Some(s) = session.get() {
                    has_permission(&s, "read_users")
                } else {
                    false
                }
            }>
                <NavTab
                    href="/users"
                    icon=UsersIcon
                    label="Users"
                    active=move || location.pathname.get().starts_with("/users")
                />
            </Show>

            <Show when=move || {
                if let Some(s) = session.get() {
                    has_permission(&s, "read_policy")
                } else {
                    false
                }
            }>
                <NavTab
                    href="/policies"
                    icon=LockIcon
                    label="Access Control"
                    active=move || location.pathname.get().starts_with("/policies")
                />
            </Show>

            <Show when=move || {
                if let Some(s) = session.get() {
                    has_permission(&s, "read_network")
                } else {
                    false
                }
            }>
                <NavTab
                    href="/dns"
                    icon=GlobeIcon
                    label="DNS"
                    active=move || location.pathname.get().starts_with("/dns")
                />
            </Show>

            <Show when=move || {
                if let Some(s) = session.get() {
                    has_permission(&s, "read_settings")
                } else {
                    false
                }
            }>
                <NavTab
                    href="/settings"
                    icon=SettingsIcon
                    label="Settings"
                    active=move || location.pathname.get().starts_with("/settings")
                />
            </Show>
        </nav>
    }
}

#[component]
fn NavTab<F>(
    href: &'static str,
    icon: F,
    label: &'static str,
    #[prop(into)]
    active: Signal<bool>,
) -> impl IntoView
where
    F: Fn() -> impl IntoView + 'static,
{
    view! {
        <A
            href=href
            class=move || format!(
                "inline-flex items-center px-3 py-2 text-sm font-medium rounded-t-lg transition-colors relative {}",
                if active.get() {
                    "text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400"
                } else {
                    "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                }
            )
        >
            <span class="flex items-center space-x-2">
                <span class="w-5 h-5">{icon()}</span>
                <span>{label}</span>
            </span>
        </A>
    }
}

#[component]
fn UserMenu(
    #[prop(into)]
    session: Signal<Option<AuthSession>>,
) -> impl IntoView {
    let auth = use_auth();
    let (show_menu, set_show_menu) = create_signal(false);

    let user = move || session.get().map(|s| s.user);

    let handle_logout = move |_| {
        auth.logout.dispatch(());
        set_show_menu.set(false);
    };

    view! {
        <div class="relative">
            <button
                on:click=move |_| set_show_menu.update(|show| *show = !*show)
                class="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
                <Show
                    when=move || user().and_then(|u| u.email.clone()).is_some()
                    fallback=|| view! {
                        <UserIcon class="w-6 h-6 text-gray-600 dark:text-gray-400"/>
                    }
                >
                    <div class="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                        <span class="text-white text-sm font-medium">
                            {move || user()
                                .and_then(|u| u.name.chars().next())
                                .unwrap_or('U')
                                .to_uppercase()
                            }
                        </span>
                    </div>
                </Show>
            </button>

            <Show when=move || show_menu.get()>
                <div class="absolute right-0 mt-2 w-64 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50">
                    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                        <Show when=move || user().is_some()>
                            {move || {
                                let u = user().unwrap();
                                view! {
                                    <div>
                                        <p class="font-medium text-gray-900 dark:text-white">
                                            {u.name}
                                        </p>
                                        <Show when=move || u.email.is_some()>
                                            <p class="text-sm text-gray-600 dark:text-gray-400">
                                                {u.email.unwrap_or_default()}
                                            </p>
                                        </Show>
                                        <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                                            "Role: " {u.role}
                                        </p>
                                    </div>
                                }
                            }}
                        </Show>
                    </div>

                    <div class="p-2">
                        <button
                            on:click=handle_logout
                            class="w-full text-left px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors"
                        >
                            "Sign Out"
                        </button>
                    </div>
                </div>
            </Show>

            {/* Backdrop to close menu */}
            <Show when=move || show_menu.get()>
                <div
                    class="fixed inset-0 z-40"
                    on:click=move |_| set_show_menu.set(false)
                ></div>
            </Show>
        </div>
    }
}