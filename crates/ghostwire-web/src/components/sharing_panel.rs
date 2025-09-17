/// Device sharing and access control panel
///
/// Provides Tailscale-like sharing functionality for managing device access,
/// subnet routes, exit node configuration, and tagging.

use leptos::*;
use leptos_router::*;

use crate::types::{Node, User, Tag, SharePermission};
use crate::components::icons::*;
use crate::components::notifications::use_notifications;

#[component]
pub fn SharingPanel(
    #[prop(into)]
    machine: Signal<Option<Node>>,
    #[prop(into)]
    users: Signal<Vec<User>>,
) -> impl IntoView {
    let notifications = use_notifications();
    let (active_tab, set_active_tab) = create_signal("sharing".to_string());

    view! {
        <Show when=move || machine.get().is_some()>
            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                {/* Header */}
                <div class="border-b border-gray-200 dark:border-gray-700 p-4">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                        "Sharing & Access"
                    </h3>
                    <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        "Configure sharing settings and access permissions"
                    </p>
                </div>

                {/* Tabs */}
                <div class="border-b border-gray-200 dark:border-gray-700">
                    <nav class="flex space-x-8 px-4">
                        <SharingTabButton
                            label="Sharing"
                            value="sharing"
                            active=active_tab
                            on_click=set_active_tab
                        />
                        <SharingTabButton
                            label="Routes"
                            value="routes"
                            active=active_tab
                            on_click=set_active_tab
                        />
                        <SharingTabButton
                            label="Exit Node"
                            value="exit"
                            active=active_tab
                            on_click=set_active_tab
                        />
                        <SharingTabButton
                            label="Tags"
                            value="tags"
                            active=active_tab
                            on_click=set_active_tab
                        />
                    </nav>
                </div>

                {/* Content */}
                <div class="p-4">
                    <Show when=move || active_tab.get() == "sharing">
                        <SharingTab machine=machine users=users />
                    </Show>
                    <Show when=move || active_tab.get() == "routes">
                        <RoutesTab machine=machine />
                    </Show>
                    <Show when=move || active_tab.get() == "exit">
                        <ExitNodeTab machine=machine />
                    </Show>
                    <Show when=move || active_tab.get() == "tags">
                        <TagsTab machine=machine />
                    </Show>
                </div>
            </div>
        </Show>
    }
}

#[component]
fn SharingTabButton(
    label: &'static str,
    value: &'static str,
    #[prop(into)]
    active: Signal<String>,
    on_click: WriteSignal<String>,
) -> impl IntoView {
    let is_active = move || active.get() == value;

    view! {
        <button
            on:click=move |_| on_click.set(value.to_string())
            class=move || format!(
                "py-3 px-1 border-b-2 font-medium text-sm transition-colors {}",
                if is_active() {
                    "border-blue-500 text-blue-600 dark:text-blue-400"
                } else {
                    "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
                }
            )
        >
            {label}
        </button>
    }
}

#[component]
fn SharingTab(
    #[prop(into)]
    machine: Signal<Option<Node>>,
    #[prop(into)]
    users: Signal<Vec<User>>,
) -> impl IntoView {
    let (share_with_user, set_share_with_user) = create_signal(String::new());
    let (permission_level, set_permission_level) = create_signal("view".to_string());
    let notifications = use_notifications();

    let handle_share = move |_| {
        let user = share_with_user.get();
        let permission = permission_level.get();

        if user.is_empty() {
            notifications.show_error.call(("Error".to_string(), Some("Please select a user".to_string())));
            return;
        }

        // In a real app, this would call the API
        notifications.show_success.call((
            "Device Shared".to_string(),
            Some(format!("Shared with {} with {} permissions", user, permission))
        ));

        set_share_with_user.set(String::new());
    };

    view! {
        <div class="space-y-6">
            {/* Current sharing */}
            <div>
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Currently shared with"
                </h4>

                <div class="space-y-2">
                    {/* Mock shared users */}
                    <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div class="flex items-center space-x-3">
                            <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                                <span class="text-white text-sm font-medium">"JD"</span>
                            </div>
                            <div>
                                <p class="text-sm font-medium text-gray-900 dark:text-white">"john.doe@example.com"</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">"Admin access"</p>
                            </div>
                        </div>
                        <button class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300">
                            <TrashIcon/>
                        </button>
                    </div>

                    <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div class="flex items-center space-x-3">
                            <div class="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                                <span class="text-white text-sm font-medium">"AS"</span>
                            </div>
                            <div>
                                <p class="text-sm font-medium text-gray-900 dark:text-white">"alice.smith@example.com"</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">"View only"</p>
                            </div>
                        </div>
                        <button class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300">
                            <TrashIcon/>
                        </button>
                    </div>
                </div>
            </div>

            {/* Share with new user */}
            <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Share with new user"
                </h4>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                        <label class="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                            "User"
                        </label>
                        <select
                            class="ghostwire-input text-sm"
                            prop:value=share_with_user
                            on:change=move |ev| set_share_with_user.set(event_target_value(&ev))
                        >
                            <option value="">"Select user..."</option>
                            <For
                                each=users
                                key=|user| user.id.clone()
                                children=move |user| {
                                    view! {
                                        <option value=user.email.clone()>{user.name.clone()}</option>
                                    }
                                }
                            />
                        </select>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                            "Permission"
                        </label>
                        <select
                            class="ghostwire-input text-sm"
                            prop:value=permission_level
                            on:change=move |ev| set_permission_level.set(event_target_value(&ev))
                        >
                            <option value="view">"View only"</option>
                            <option value="admin">"Admin"</option>
                        </select>
                    </div>

                    <div class="flex items-end">
                        <button
                            class="ghostwire-btn-primary text-sm w-full"
                            on:click=handle_share
                        >
                            "Share"
                        </button>
                    </div>
                </div>
            </div>

            {/* Share link */}
            <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Share via link"
                </h4>

                <div class="flex items-center space-x-3">
                    <input
                        type="text"
                        class="ghostwire-input text-sm flex-1 font-mono"
                        value="https://ghostwire.example.com/share/abc123def456"
                        readonly
                    />
                    <button class="ghostwire-btn-secondary text-sm">
                        <CopyIcon/>
                        "Copy"
                    </button>
                    <button class="ghostwire-btn-secondary text-sm">
                        <RefreshIcon/>
                        "New"
                    </button>
                </div>

                <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
                    "Anyone with this link can view this device. Link expires in 24 hours."
                </p>
            </div>
        </div>
    }
}

#[component]
fn RoutesTab(
    #[prop(into)]
    machine: Signal<Option<Node>>,
) -> impl IntoView {
    let (new_route, set_new_route) = create_signal(String::new());
    let notifications = use_notifications();

    let handle_add_route = move |_| {
        let route = new_route.get();
        if route.is_empty() {
            notifications.show_error.call(("Error".to_string(), Some("Please enter a route".to_string())));
            return;
        }

        // Validate CIDR format
        if !route.contains('/') {
            notifications.show_error.call(("Error".to_string(), Some("Please enter a valid CIDR (e.g., 192.168.1.0/24)".to_string())));
            return;
        }

        notifications.show_success.call(("Route Added".to_string(), Some(format!("Added subnet route: {}", route))));
        set_new_route.set(String::new());
    };

    view! {
        <div class="space-y-6">
            <div>
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Advertised subnet routes"
                </h4>

                {/* Current routes */}
                <div class="space-y-2 mb-4">
                    <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div>
                            <code class="text-sm font-mono text-gray-900 dark:text-white">"192.168.1.0/24"</code>
                            <p class="text-xs text-gray-500 dark:text-gray-400">"Home network"</p>
                        </div>
                        <button class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300">
                            <TrashIcon/>
                        </button>
                    </div>

                    <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div>
                            <code class="text-sm font-mono text-gray-900 dark:text-white">"10.0.0.0/8"</code>
                            <p class="text-xs text-gray-500 dark:text-gray-400">"Corporate network"</p>
                        </div>
                        <button class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300">
                            <TrashIcon/>
                        </button>
                    </div>
                </div>

                {/* Add new route */}
                <div class="flex items-center space-x-3">
                    <input
                        type="text"
                        class="ghostwire-input text-sm flex-1"
                        placeholder="192.168.1.0/24"
                        prop:value=new_route
                        on:input=move |ev| set_new_route.set(event_target_value(&ev))
                    />
                    <button
                        class="ghostwire-btn-primary text-sm"
                        on:click=handle_add_route
                    >
                        "Add Route"
                    </button>
                </div>

                <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
                    "Subnet routes allow other devices to access networks behind this machine."
                </p>
            </div>

            {/* Route approval */}
            <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Pending approval"
                </h4>

                <div class="space-y-2">
                    <div class="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
                        <div>
                            <code class="text-sm font-mono text-gray-900 dark:text-white">"172.16.0.0/16"</code>
                            <p class="text-xs text-yellow-700 dark:text-yellow-400">"Waiting for admin approval"</p>
                        </div>
                        <div class="flex space-x-2">
                            <button class="text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300">
                                <CheckIcon/>
                            </button>
                            <button class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300">
                                <XIcon/>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn ExitNodeTab(
    #[prop(into)]
    machine: Signal<Option<Node>>,
) -> impl IntoView {
    let (exit_node_enabled, set_exit_node_enabled) = create_signal(false);
    let (allow_lan_access, set_allow_lan_access) = create_signal(true);
    let notifications = use_notifications();

    let handle_toggle_exit_node = move |enabled: bool| {
        set_exit_node_enabled.set(enabled);

        let message = if enabled {
            "Exit node enabled - other devices can now route internet traffic through this machine"
        } else {
            "Exit node disabled"
        };

        notifications.show_info.call(("Exit Node".to_string(), Some(message.to_string())));
    };

    view! {
        <div class="space-y-6">
            <div>
                <div class="flex items-center justify-between">
                    <div>
                        <h4 class="text-sm font-medium text-gray-900 dark:text-white">
                            "Use as exit node"
                        </h4>
                        <p class="text-xs text-gray-500 dark:text-gray-400">
                            "Route internet traffic through this device"
                        </p>
                    </div>
                    <label class="relative inline-flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            class="sr-only"
                            prop:checked=exit_node_enabled
                            on:change=move |ev| handle_toggle_exit_node(event_target_checked(&ev))
                        />
                        <div class=move || format!(
                            "w-11 h-6 rounded-full transition-colors {}",
                            if exit_node_enabled.get() { "bg-blue-600" } else { "bg-gray-200 dark:bg-gray-700" }
                        )></div>
                        <div class=move || format!(
                            "absolute w-4 h-4 bg-white rounded-full transition-transform {}",
                            if exit_node_enabled.get() { "translate-x-6" } else { "translate-x-1" }
                        )></div>
                    </label>
                </div>
            </div>

            <Show when=move || exit_node_enabled.get()>
                <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <h4 class="text-sm font-medium text-gray-900 dark:text-white">
                                "Allow LAN access"
                            </h4>
                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                "Allow access to local network while using as exit node"
                            </p>
                        </div>
                        <label class="relative inline-flex items-center cursor-pointer">
                            <input
                                type="checkbox"
                                class="sr-only"
                                prop:checked=allow_lan_access
                                on:change=move |ev| set_allow_lan_access.set(event_target_checked(&ev))
                            />
                            <div class=move || format!(
                                "w-11 h-6 rounded-full transition-colors {}",
                                if allow_lan_access.get() { "bg-blue-600" } else { "bg-gray-200 dark:bg-gray-700" }
                            )></div>
                            <div class=move || format!(
                                "absolute w-4 h-4 bg-white rounded-full transition-transform {}",
                                if allow_lan_access.get() { "translate-x-6" } else { "translate-x-1" }
                            )></div>
                        </label>
                    </div>

                    <div class="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
                        <div class="flex">
                            <InfoIcon/>
                            <div class="ml-3">
                                <h5 class="text-sm font-medium text-blue-800 dark:text-blue-400">
                                    "Exit node requirements"
                                </h5>
                                <ul class="mt-1 text-xs text-blue-700 dark:text-blue-300 list-disc list-inside space-y-1">
                                    <li>"IP forwarding must be enabled on this device"</li>
                                    <li>"Firewall rules may need to be configured"</li>
                                    <li>"Higher bandwidth usage expected"</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </Show>

            <Show when=move || !exit_node_enabled.get()>
                <div class="text-center py-8">
                    <GlobeIcon/>
                    <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                        "Exit node functionality is disabled"
                    </p>
                    <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                        "Enable to allow other devices to route internet traffic through this machine"
                    </p>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn TagsTab(
    #[prop(into)]
    machine: Signal<Option<Node>>,
) -> impl IntoView {
    let (new_tag, set_new_tag) = create_signal(String::new());
    let notifications = use_notifications();

    let handle_add_tag = move |_| {
        let tag = new_tag.get().trim().to_string();
        if tag.is_empty() {
            notifications.show_error.call(("Error".to_string(), Some("Please enter a tag".to_string())));
            return;
        }

        notifications.show_success.call(("Tag Added".to_string(), Some(format!("Added tag: {}", tag))));
        set_new_tag.set(String::new());
    };

    view! {
        <div class="space-y-6">
            <div>
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Applied tags"
                </h4>

                <div class="flex flex-wrap gap-2 mb-4">
                    {/* Current tags */}
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                        "tag:production"
                        <button class="ml-1 text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300">
                            <XIcon/>
                        </button>
                    </span>

                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400">
                        "tag:web-server"
                        <button class="ml-1 text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300">
                            <XIcon/>
                        </button>
                    </span>

                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400">
                        "tag:east-coast"
                        <button class="ml-1 text-purple-600 dark:text-purple-400 hover:text-purple-800 dark:hover:text-purple-300">
                            <XIcon/>
                        </button>
                    </span>
                </div>

                {/* Add new tag */}
                <div class="flex items-center space-x-3">
                    <input
                        type="text"
                        class="ghostwire-input text-sm flex-1"
                        placeholder="tag:database"
                        prop:value=new_tag
                        on:input=move |ev| set_new_tag.set(event_target_value(&ev))
                    />
                    <button
                        class="ghostwire-btn-primary text-sm"
                        on:click=handle_add_tag
                    >
                        "Add Tag"
                    </button>
                </div>

                <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
                    "Tags are used for ACL policies and organizing devices. Use format 'tag:name'."
                </p>
            </div>

            {/* Suggested tags */}
            <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">
                    "Suggested tags"
                </h4>

                <div class="flex flex-wrap gap-2">
                    <button class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                        "tag:server"
                        <PlusIcon/>
                    </button>
                    <button class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                        "tag:development"
                        <PlusIcon/>
                    </button>
                    <button class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                        "tag:backup"
                        <PlusIcon/>
                    </button>
                </div>
            </div>

            {/* ACL info */}
            <div class="border-t border-gray-200 dark:border-gray-700 pt-6">
                <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="flex">
                        <InfoIcon/>
                        <div class="ml-3">
                            <h5 class="text-sm font-medium text-gray-900 dark:text-white">
                                "Tags and ACLs"
                            </h5>
                            <p class="mt-1 text-xs text-gray-600 dark:text-gray-400">
                                "Tags are used in ACL policies to control network access. Changes to tags may affect connectivity."
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}