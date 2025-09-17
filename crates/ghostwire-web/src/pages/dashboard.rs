/// Dashboard overview page
///
/// Main landing page showing system status, key metrics, and recent activity.

use leptos::*;

use crate::auth::use_auth;
use crate::types::{SystemStatus, Node, DerpRegion, Route};
use crate::components::icons::*;
use crate::components::network_topology::NetworkTopology;
use crate::api::machines::fetch_machines;
use crate::utils::time::format_relative_time;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let auth = use_auth();

    // Load dashboard data
    let system_status = create_resource(
        || (),
        |_| async move {
            // Mock system status for now
            SystemStatus {
                server_version: "0.1.0".to_string(),
                uptime: "2d 14h 32m".to_string(),
                connected_nodes: 42,
                active_connections: 128,
                cpu_usage: 12.3,
                memory_usage: "245MB / 1GB".to_string(),
                network_traffic: crate::types::NetworkTraffic {
                    bytes_in: 1024 * 1024 * 512, // 512 MB
                    bytes_out: 1024 * 1024 * 1024 * 2, // 2 GB
                    packets_in: 125000,
                    packets_out: 230000,
                },
                derp_relays: vec![
                    crate::types::DerpRelayStatus {
                        region: "us-east".to_string(),
                        healthy: true,
                        latency: Some(45),
                        clients: 15,
                    },
                    crate::types::DerpRelayStatus {
                        region: "eu-west".to_string(),
                        healthy: true,
                        latency: Some(78),
                        clients: 20,
                    },
                    crate::types::DerpRelayStatus {
                        region: "asia-pacific".to_string(),
                        healthy: false,
                        latency: None,
                        clients: 0,
                    },
                ],
            }
        }
    );

    let all_machines = create_resource(
        || (),
        |_| async move {
            fetch_machines().await.unwrap_or_default()
        }
    );

    let recent_machines = move || {
        all_machines.get()
            .and_then(|result| result.ok())
            .unwrap_or_default()
            .into_iter()
            .take(5)
            .collect::<Vec<_>>()
    };

    // Mock data for network topology
    let routes = create_signal(Vec::<Route>::new()).0;
    let derp_regions = create_signal(vec![
        DerpRegion {
            id: 1,
            name: "US East".to_string(),
            nodes: vec![],
            avoid: false,
        },
        DerpRegion {
            id: 2,
            name: "EU West".to_string(),
            nodes: vec![],
            avoid: false,
        },
    ]).0;

    view! {
        <div class="space-y-6">
            {/* Page header */}
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "Dashboard"
                </h1>
                <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    "Overview of your GhostWire mesh network"
                </p>
            </div>

            {/* Status cards */}
            <Suspense fallback=move || view! {
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <For each=|| 0..4 key=|i| *i children=move |_| {
                        view! { <SkeletonCard/> }
                    }/>
                </div>
            }>
                {move || system_status.get().map(|status_result| {
                    status_result.map(|status| {
                        view! { <StatusCards status=status /> }
                    }).unwrap_or_else(|_| view! {
                        <div class="text-red-600 dark:text-red-400">"Failed to load system status"</div>
                    })
                })}
            </Suspense>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Recent machines */}
                <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-lg font-medium text-gray-900 dark:text-white">
                            "Recent Machines"
                        </h2>
                        <a
                            href="/machines"
                            class="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300"
                        >
                            "View all"
                        </a>
                    </div>

                    <Suspense fallback=move || view! { <div>"Loading machines..."</div> }>
                        {move || {
                            let machines = recent_machines();
                            if machines.is_empty() {
                                view! {
                                    <div class="text-center py-8">
                                        <ServerIcon/>
                                        <p class="mt-2 text-gray-600 dark:text-gray-400">"No machines yet"</p>
                                    </div>
                                }.into_view()
                            } else {
                                view! {
                                    <div class="space-y-3">
                                        <For
                                            each=move || machines.clone()
                                            key=|machine| machine.id.clone()
                                            children=move |machine| {
                                                view! { <MachineItem machine=machine /> }
                                            }
                                        />
                                    </div>
                                }.into_view()
                            }
                        }}
                    </Suspense>
                </div>

                {/* DERP relay status */}
                <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">
                        "DERP Relays"
                    </h2>

                    <Suspense fallback=move || view! { <div>"Loading DERP status..."</div> }>
                        {move || system_status.get().map(|status_result| {
                            status_result.map(|status| {
                                view! {
                                    <div class="space-y-3">
                                        <For
                                            each=move || status.derp_relays.clone()
                                            key=|relay| relay.region.clone()
                                            children=move |relay| {
                                                view! { <DerpRelayItem relay=relay /> }
                                            }
                                        />
                                    </div>
                                }
                            }).unwrap_or_else(|_| view! {
                                <div class="text-red-600 dark:text-red-400">"Failed to load DERP status"</div>
                            })
                        })}
                    </Suspense>
                </div>
            </div>

            {/* Network Topology */}
            <Suspense fallback=move || view! {
                <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
                    <div class="animate-pulse">
                        <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-48 mx-auto mb-4"></div>
                        <div class="h-96 bg-gray-200 dark:bg-gray-700 rounded"></div>
                    </div>
                </div>
            }>
                {move || all_machines.get().map(|machines_result| {
                    machines_result.map(|machines| {
                        let nodes_signal = create_signal(machines).0;
                        view! {
                            <NetworkTopology
                                nodes=nodes_signal.into()
                                routes=routes.into()
                                derp_regions=derp_regions.into()
                            />
                        }
                    }).unwrap_or_else(|_| view! {
                        <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
                            <p class="text-red-600 dark:text-red-400">"Failed to load network topology"</p>
                        </div>
                    })
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn StatusCards(status: SystemStatus) -> impl IntoView {
    let format_bytes = |bytes: u64| -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes as f64;
        let mut unit_index = 0;

        while value >= 1024.0 && unit_index < UNITS.len() - 1 {
            value /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", value, UNITS[unit_index])
        }
    };

    view! {
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <StatusCard
                title="Connected Machines"
                value=status.connected_nodes.to_string()
                icon=ServerIcon
                color="blue"
            />
            <StatusCard
                title="Active Connections"
                value=status.active_connections.to_string()
                icon=NetworkIcon
                color="green"
            />
            <StatusCard
                title="CPU Usage"
                value=format!("{:.1}%", status.cpu_usage)
                icon=DashboardIcon
                color="yellow"
            />
            <StatusCard
                title="Network Traffic"
                value=format!("{} out", format_bytes(status.network_traffic.bytes_out))
                icon=GlobeIcon
                color="purple"
            />
        </div>
    }
}

#[component]
fn StatusCard<F>(
    title: &'static str,
    value: String,
    icon: F,
    color: &'static str,
) -> impl IntoView
where
    F: Fn() -> impl IntoView + 'static,
{
    let (bg_class, text_class) = match color {
        "blue" => ("bg-blue-50 dark:bg-blue-900/20", "text-blue-600 dark:text-blue-400"),
        "green" => ("bg-green-50 dark:bg-green-900/20", "text-green-600 dark:text-green-400"),
        "yellow" => ("bg-yellow-50 dark:bg-yellow-900/20", "text-yellow-600 dark:text-yellow-400"),
        "purple" => ("bg-purple-50 dark:bg-purple-900/20", "text-purple-600 dark:text-purple-400"),
        _ => ("bg-gray-50 dark:bg-gray-900/20", "text-gray-600 dark:text-gray-400"),
    };

    view! {
        <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div class="flex items-center">
                <div class=format!("p-2 rounded-lg {}", bg_class)>
                    <div class=format!("w-6 h-6 {}", text_class)>
                        {icon()}
                    </div>
                </div>
                <div class="ml-4">
                    <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                        {title}
                    </p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white">
                        {value}
                    </p>
                </div>
            </div>
        </div>
    }
}

#[component]
fn MachineItem(machine: Node) -> impl IntoView {
    let status_class = if machine.online {
        "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
    } else {
        "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400"
    };

    let last_seen = machine.last_seen
        .map(|dt| format_relative_time(dt))
        .unwrap_or_else(|| "Never".to_string());

    view! {
        <div class="flex items-center space-x-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
            <div class="flex-1">
                <div class="flex items-center space-x-2">
                    <p class="text-sm font-medium text-gray-900 dark:text-white">
                        {machine.name}
                    </p>
                    <span class=format!("inline-flex px-2 py-1 text-xs font-semibold rounded-full {}", status_class)>
                        {if machine.online { "Online" } else { "Offline" }}
                    </span>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400">
                    {machine.ip_addresses.join(", ")} • {last_seen}
                </p>
            </div>
        </div>
    }
}

#[component]
fn DerpRelayItem(relay: crate::types::DerpRelayStatus) -> impl IntoView {
    let status_class = if relay.healthy {
        "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
    } else {
        "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400"
    };

    let latency_text = relay.latency
        .map(|l| format!("{}ms", l))
        .unwrap_or_else(|| "N/A".to_string());

    view! {
        <div class="flex items-center space-x-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
            <div class="flex-1">
                <div class="flex items-center space-x-2">
                    <p class="text-sm font-medium text-gray-900 dark:text-white">
                        {relay.region}
                    </p>
                    <span class=format!("inline-flex px-2 py-1 text-xs font-semibold rounded-full {}", status_class)>
                        {if relay.healthy { "Healthy" } else { "Unhealthy" }}
                    </span>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400">
                    {format!("{} clients • {} latency", relay.clients, latency_text)}
                </p>
            </div>
        </div>
    }
}

#[component]
fn SkeletonCard() -> impl IntoView {
    view! {
        <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 animate-pulse">
            <div class="flex items-center">
                <div class="w-12 h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                <div class="ml-4 space-y-2">
                    <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-20"></div>
                    <div class="h-6 bg-gray-200 dark:bg-gray-700 rounded w-16"></div>
                </div>
            </div>
        </div>
    }
}