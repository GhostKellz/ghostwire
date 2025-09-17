/// Machines/Nodes management page
///
/// Interface for viewing and managing connected devices in the mesh network.
/// Inspired by headplane's machines overview with real-time updates.

use leptos::*;
use leptos_router::*;

use crate::auth::use_auth;
use crate::types::{Node, User};
use crate::components::icons::*;
use crate::components::machine_details::MachineDetailsModal;
use crate::components::notifications::use_notifications;
use crate::api::machines::*;
use crate::utils::time::*;

#[component]
pub fn MachinesPage() -> impl IntoView {
    let auth = use_auth();

    // Load machines data
    let machines_resource = create_resource(
        || (),
        |_| async move {
            // This would normally use the API client
            fetch_machines().await
        }
    );

    // Load users for filtering
    let users_resource = create_resource(
        || (),
        |_| async move {
            fetch_users().await
        }
    );

    let (filter_user, set_filter_user) = create_signal::<Option<String>>(None);
    let (filter_status, set_filter_status) = create_signal::<Option<String>>(None);
    let (search_query, set_search_query) = create_signal(String::new());

    // Machine details modal state
    let (selected_machine, set_selected_machine) = create_signal::<Option<Node>>(None);
    let (show_details, set_show_details) = create_signal(false);

    let notifications = use_notifications();

    // Filter machines based on current filters
    let filtered_machines = move || {
        machines_resource.get()
            .and_then(|result| result.ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|machine| {
                // Filter by user
                if let Some(user_filter) = filter_user.get() {
                    if machine.user != user_filter {
                        return false;
                    }
                }

                // Filter by status
                if let Some(status_filter) = filter_status.get() {
                    match status_filter.as_str() {
                        "online" => if !machine.online { return false; },
                        "offline" => if machine.online { return false; },
                        _ => {}
                    }
                }

                // Filter by search query
                let query = search_query.get().to_lowercase();
                if !query.is_empty() {
                    let matches_name = machine.name.to_lowercase().contains(&query);
                    let matches_hostname = machine.hostname.to_lowercase().contains(&query);
                    let matches_ip = machine.ip_addresses.iter().any(|ip| ip.contains(&query));

                    if !matches_name && !matches_hostname && !matches_ip {
                        return false;
                    }
                }

                true
            })
            .collect::<Vec<_>>()
    };

    view! {
        <div class="space-y-6">
            {/* Page header */}
            <div class="flex justify-between items-start">
                <div>
                    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                        "Machines"
                    </h1>
                    <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        "Manage the devices connected to your GhostWire network"
                    </p>
                </div>

                <div class="flex space-x-3">
                    <button class="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        "Add Machine"
                    </button>
                </div>
            </div>

            {/* Filters and search */}
            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            "Search"
                        </label>
                        <input
                            type="text"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            placeholder="Search machines..."
                            prop:value=search_query
                            on:input=move |ev| set_search_query.set(event_target_value(&ev))
                        />
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            "User"
                        </label>
                        <select
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            on:change=move |ev| {
                                let value = event_target_value(&ev);
                                set_filter_user.set(if value.is_empty() { None } else { Some(value) });
                            }
                        >
                            <option value="">"All Users"</option>
                            <Suspense fallback=|| view! { <option>"Loading..."</option> }>
                                {move || users_resource.get().map(|users_result| {
                                    users_result.map(|users| {
                                        users.into_iter().map(|user| {
                                            view! {
                                                <option value=user.name.clone()>{user.name}</option>
                                            }
                                        }).collect_view()
                                    }).unwrap_or_default()
                                })}
                            </Suspense>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            "Status"
                        </label>
                        <select
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            on:change=move |ev| {
                                let value = event_target_value(&ev);
                                set_filter_status.set(if value.is_empty() { None } else { Some(value) });
                            }
                        >
                            <option value="">"All Status"</option>
                            <option value="online">"Online"</option>
                            <option value="offline">"Offline"</option>
                        </select>
                    </div>

                    <div class="flex items-end">
                        <button
                            class="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                            on:click=move |_| {
                                set_filter_user.set(None);
                                set_filter_status.set(None);
                                set_search_query.set(String::new());
                            }
                        >
                            "Clear Filters"
                        </button>
                    </div>
                </div>
            </div>

            {/* Machines table */}
            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                <Suspense fallback=move || view! {
                    <div class="p-8 text-center">
                        <LoadingIcon/>
                        <p class="mt-2 text-gray-600 dark:text-gray-400">"Loading machines..."</p>
                    </div>
                }>
                    <ErrorBoundary fallback=|errors| view! {
                        <div class="p-8 text-center">
                            <AlertIcon/>
                            <p class="mt-2 text-red-600 dark:text-red-400">"Failed to load machines"</p>
                            <p class="text-sm text-gray-500 mt-1">{format!("{:?}", errors)}</p>
                        </div>
                    }>
                        <MachinesTable
                            machines=filtered_machines
                            on_machine_click=move |machine: Node| {
                                set_selected_machine.set(Some(machine));
                                set_show_details.set(true);
                            }
                        />
                    </ErrorBoundary>
                </Suspense>
            </div>

            {/* Machine Details Modal */}
            <MachineDetailsModal
                machine=selected_machine.into()
                show=show_details.into()
                on_close=move || set_show_details.set(false)
            />
        </div>
    }
}

#[component]
fn MachinesTable(
    #[prop(into)]
    machines: Signal<Vec<Node>>,
    on_machine_click: Callback<Node>,
) -> impl IntoView {
    view! {
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-900">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Name"
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Addresses"
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "User"
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Status"
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Last Seen"
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Actions"
                        </th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    <For
                        each=machines
                        key=|machine| machine.id.clone()
                        children=move |machine| {
                            view! { <MachineRow machine=machine.clone() on_click=on_machine_click /> }
                        }
                    />
                </tbody>
            </table>

            <Show when=move || machines.get().is_empty()>
                <div class="p-8 text-center">
                    <ServerIcon/>
                    <p class="mt-2 text-gray-600 dark:text-gray-400">"No machines found"</p>
                    <p class="text-sm text-gray-500 dark:text-gray-500 mt-1">
                        "Try adjusting your filters or add a new machine"
                    </p>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn MachineRow(
    machine: Node,
    on_click: Callback<Node>,
) -> impl IntoView {
    let status_class = if machine.online {
        "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
    } else {
        "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400"
    };

    let status_text = if machine.online { "Online" } else { "Offline" };

    let last_seen = machine.last_seen
        .map(|dt| format_relative_time(dt))
        .unwrap_or_else(|| "Never".to_string());

    view! {
        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
            on:click=move |_| on_click.call(machine.clone())
        >
            <td class="px-6 py-4 whitespace-nowrap">
                <div>
                    <div class="text-sm font-medium text-gray-900 dark:text-white">
                        {machine.name.clone()}
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">
                        {machine.hostname}
                    </div>
                </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-900 dark:text-white">
                    {machine.ip_addresses.join(", ")}
                </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-900 dark:text-white">
                    {machine.user}
                </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class=format!("inline-flex px-2 py-1 text-xs font-semibold rounded-full {}", status_class)>
                    {status_text}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                {last_seen}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <div class="flex space-x-2">
                    <button class="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300">
                        "Edit"
                    </button>
                    <button class="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300">
                        "Delete"
                    </button>
                </div>
            </td>
        </tr>
    }
}