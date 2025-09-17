/// Advanced machine details modal with Tailscale-like functionality
///
/// Comprehensive machine management interface with routes, tags, sharing, and actions.

use leptos::*;
use leptos_router::*;

use crate::types::{Node, Route, User, PreAuthKey};
use crate::components::icons::*;
use crate::components::notifications::use_notifications;
use crate::utils::time::format_relative_time;

#[component]
pub fn MachineDetailsModal(
    #[prop(into)]
    machine: Signal<Option<Node>>,
    #[prop(into)]
    show: Signal<bool>,
    on_close: Callback<()>,
) -> impl IntoView {
    let notifications = use_notifications();

    view! {
        <Show when=move || show.get() && machine.get().is_some()>
            <div class="fixed inset-0 z-50 overflow-y-auto">
                <div class="flex items-center justify-center min-h-screen p-4">
                    {/* Backdrop */}
                    <div
                        class="fixed inset-0 bg-black bg-opacity-50 transition-opacity"
                        on:click=move |_| on_close.call(())
                    ></div>

                    {/* Modal */}
                    <div class="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
                        {move || machine.get().map(|m| view! {
                            <MachineDetailsContent machine=m on_close=on_close />
                        })}
                    </div>
                </div>
            </div>
        </Show>
    }
}

#[component]
fn MachineDetailsContent(
    machine: Node,
    on_close: Callback<()>,
) -> impl IntoView {
    let (active_tab, set_active_tab) = create_signal("overview".to_string());
    let notifications = use_notifications();

    let handle_action = move |action: &str| {
        match action {
            "rename" => {
                notifications.show_info.call(("Rename".to_string(), Some("Rename functionality not yet implemented".to_string())));
            }
            "delete" => {
                notifications.show_warning.call(("Delete Machine".to_string(), Some("This action cannot be undone".to_string())));
            }
            "disable" => {
                notifications.show_info.call(("Disable".to_string(), Some("Machine will be disconnected".to_string())));
            }
            _ => {}
        }
    };

    view! {
        <div class="flex flex-col h-full">
            {/* Header */}
            <div class="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
                <div class="flex items-center space-x-4">
                    <div class=format!(
                        "w-3 h-3 rounded-full {}",
                        if machine.online { "bg-green-500" } else { "bg-red-500" }
                    )></div>
                    <div>
                        <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
                            {machine.name.clone()}
                        </h2>
                        <p class="text-sm text-gray-600 dark:text-gray-400">
                            {machine.hostname.clone()} • {machine.user.clone()}
                        </p>
                    </div>
                </div>

                <div class="flex items-center space-x-2">
                    <MachineActionMenu machine=machine.clone() on_action=handle_action />
                    <button
                        on:click=move |_| on_close.call(())
                        class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                    >
                        <CloseIcon/>
                    </button>
                </div>
            </div>

            {/* Tabs */}
            <div class="border-b border-gray-200 dark:border-gray-700">
                <nav class="flex space-x-8 px-6">
                    <TabButton
                        label="Overview"
                        value="overview"
                        active=active_tab
                        on_click=set_active_tab
                    />
                    <TabButton
                        label="Routes"
                        value="routes"
                        active=active_tab
                        on_click=set_active_tab
                    />
                    <TabButton
                        label="Access"
                        value="access"
                        active=active_tab
                        on_click=set_active_tab
                    />
                    <TabButton
                        label="Activity"
                        value="activity"
                        active=active_tab
                        on_click=set_active_tab
                    />
                </nav>
            </div>

            {/* Content */}
            <div class="flex-1 overflow-y-auto p-6">
                <Show when=move || active_tab.get() == "overview">
                    <OverviewTab machine=machine.clone() />
                </Show>
                <Show when=move || active_tab.get() == "routes">
                    <RoutesTab machine=machine.clone() />
                </Show>
                <Show when=move || active_tab.get() == "access">
                    <AccessTab machine=machine.clone() />
                </Show>
                <Show when=move || active_tab.get() == "activity">
                    <ActivityTab machine=machine.clone() />
                </Show>
            </div>
        </div>
    }
}

#[component]
fn TabButton(
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
                "py-4 px-1 border-b-2 font-medium text-sm transition-colors {}",
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
fn OverviewTab(machine: Node) -> impl IntoView {
    let os_icon = match machine.os.as_deref() {
        Some("linux") => "🐧",
        Some("windows") => "🪟",
        Some("darwin") | Some("macos") => "🍎",
        Some("android") => "🤖",
        Some("ios") => "📱",
        _ => "💻",
    };

    view! {
        <div class="space-y-6">
            {/* Basic Information */}
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">"Device Information"</h3>

                    <div class="space-y-3">
                        <InfoRow
                            label="Operating System"
                            value=format!("{} {} ({})",
                                os_icon,
                                machine.os.clone().unwrap_or("Unknown".to_string()),
                                machine.arch.clone().unwrap_or("unknown".to_string())
                            )
                        />
                        <InfoRow
                            label="Version"
                            value=machine.version.clone().unwrap_or("Unknown".to_string())
                        />
                        <InfoRow
                            label="Hostname"
                            value=machine.hostname.clone()
                        />
                        <InfoRow
                            label="Owner"
                            value=machine.user.clone()
                        />
                        <InfoRow
                            label="Registration Method"
                            value=machine.register_method.clone()
                        />
                        <InfoRow
                            label="Ephemeral"
                            value=if machine.ephemeral { "Yes" } else { "No" }.to_string()
                        />
                    </div>
                </div>

                <div class="space-y-4">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">"Network"</h3>

                    <div class="space-y-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                "IP Addresses"
                            </label>
                            <div class="space-y-1">
                                <For
                                    each=move || machine.ip_addresses.clone()
                                    key=|ip| ip.clone()
                                    children=move |ip| {
                                        view! {
                                            <div class="flex items-center space-x-2">
                                                <code class="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-sm">
                                                    {ip}
                                                </code>
                                                <button
                                                    class="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                                                    on:click=move |_| {
                                                        // Copy to clipboard
                                                    }
                                                >
                                                    "Copy"
                                                </button>
                                            </div>
                                        }
                                    }
                                />
                            </div>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                "Node Key"
                            </label>
                            <code class="block px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono break-all">
                                {machine.node_key.clone()}
                            </code>
                        </div>

                        <InfoRow
                            label="Last Seen"
                            value=machine.last_seen
                                .map(|dt| format_relative_time(dt))
                                .unwrap_or_else(|| "Never".to_string())
                        />
                    </div>
                </div>
            </div>

            {/* Tags */}
            <div>
                <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">"Tags"</h3>
                <div class="flex flex-wrap gap-2">
                    <For
                        each=move || machine.tags.clone()
                        key=|tag| tag.clone()
                        children=move |tag| {
                            view! {
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                                    {tag}
                                </span>
                            }
                        }
                    />
                    <Show when=move || machine.tags.is_empty()>
                        <span class="text-sm text-gray-500 dark:text-gray-400 italic">
                            "No tags assigned"
                        </span>
                    </Show>
                </div>
            </div>

            {/* Connection Status */}
            <div>
                <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">"Connection Status"</h3>
                <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <div class="flex items-center space-x-3">
                        <div class=format!(
                            "w-3 h-3 rounded-full {}",
                            if machine.online { "bg-green-500 animate-pulse" } else { "bg-red-500" }
                        )></div>
                        <span class="font-medium text-gray-900 dark:text-white">
                            {if machine.online { "Connected" } else { "Disconnected" }}
                        </span>
                    </div>
                    <Show when=move || machine.online>
                        <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                            "This device is currently connected to the GhostWire network"
                        </p>
                    </Show>
                </div>
            </div>
        </div>
    }
}

#[component]
fn InfoRow(
    label: String,
    value: String,
) -> impl IntoView {
    view! {
        <div class="flex justify-between">
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {label}
            </span>
            <span class="text-sm text-gray-900 dark:text-white">
                {value}
            </span>
        </div>
    }
}

#[component]
fn RoutesTab(machine: Node) -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                    "Subnet Routes"
                </h3>
                <button class="ghostwire-btn-primary">
                    "Add Route"
                </button>
            </div>

            <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-8 text-center">
                <NetworkIcon/>
                <p class="mt-2 text-gray-600 dark:text-gray-400">
                    "No subnet routes configured"
                </p>
                <p class="text-sm text-gray-500 dark:text-gray-500 mt-1">
                    "Configure subnet routes to allow this machine to route traffic for specific networks"
                </p>
            </div>
        </div>
    }
}

#[component]
fn AccessTab(machine: Node) -> impl IntoView {
    view! {
        <div class="space-y-6">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                "Access Control"
            </h3>

            <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-8 text-center">
                <LockIcon/>
                <p class="mt-2 text-gray-600 dark:text-gray-400">
                    "Access control settings"
                </p>
                <p class="text-sm text-gray-500 dark:text-gray-500 mt-1">
                    "Configure sharing and access permissions for this machine"
                </p>
            </div>
        </div>
    }
}

#[component]
fn ActivityTab(machine: Node) -> impl IntoView {
    view! {
        <div class="space-y-6">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                "Activity Log"
            </h3>

            <div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-8 text-center">
                <InfoIcon/>
                <p class="mt-2 text-gray-600 dark:text-gray-400">
                    "No recent activity"
                </p>
                <p class="text-sm text-gray-500 dark:text-gray-500 mt-1">
                    "Connection events and configuration changes will appear here"
                </p>
            </div>
        </div>
    }
}

#[component]
fn MachineActionMenu(
    machine: Node,
    on_action: Callback<&'static str>,
) -> impl IntoView {
    let (show_menu, set_show_menu) = create_signal(false);

    view! {
        <div class="relative">
            <button
                on:click=move |_| set_show_menu.update(|show| *show = !*show)
                class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            >
                <MenuIcon/>
            </button>

            <Show when=move || show_menu.get()>
                <div class="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50">
                    <div class="py-1">
                        <button
                            on:click=move |_| {
                                on_action.call("rename");
                                set_show_menu.set(false);
                            }
                            class="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                            "Rename machine"
                        </button>
                        <button
                            on:click=move |_| {
                                on_action.call("disable");
                                set_show_menu.set(false);
                            }
                            class="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                            "Disable key auth"
                        </button>
                        <div class="border-t border-gray-200 dark:border-gray-700"></div>
                        <button
                            on:click=move |_| {
                                on_action.call("delete");
                                set_show_menu.set(false);
                            }
                            class="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
                        >
                            "Delete machine"
                        </button>
                    </div>
                </div>
            </Show>
        </div>
    }
}