/// Network topology visualization component
///
/// Provides a visual representation of the GhostWire mesh network
/// showing connections, paths, and relay usage similar to Tailscale's network map.

use leptos::*;
use leptos_router::*;

use crate::types::{Node, Route, DerpRegion};
use crate::components::icons::*;

#[component]
pub fn NetworkTopology(
    #[prop(into)]
    nodes: Signal<Vec<Node>>,
    #[prop(into)]
    routes: Signal<Vec<Route>>,
    #[prop(into)]
    derp_regions: Signal<Vec<DerpRegion>>,
) -> impl IntoView {
    let (layout_mode, set_layout_mode) = create_signal("geographic".to_string());
    let (selected_node, set_selected_node) = create_signal::<Option<String>>(None);

    view! {
        <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            {/* Topology Controls */}
            <div class="border-b border-gray-200 dark:border-gray-700 p-4">
                <div class="flex items-center justify-between">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                        "Network Topology"
                    </h3>

                    <div class="flex items-center space-x-4">
                        <div class="flex items-center space-x-2">
                            <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                                "Layout:"
                            </label>
                            <select
                                class="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                prop:value=layout_mode
                                on:change=move |ev| set_layout_mode.set(event_target_value(&ev))
                            >
                                <option value="geographic">"Geographic"</option>
                                <option value="logical">"Logical"</option>
                                <option value="hierarchical">"Hierarchical"</option>
                            </select>
                        </div>

                        <button class="ghostwire-btn-secondary text-sm">
                            <DownloadIcon/>
                            "Export"
                        </button>

                        <button class="ghostwire-btn-secondary text-sm">
                            <RefreshIcon/>
                            "Refresh"
                        </button>
                    </div>
                </div>
            </div>

            {/* Network Visualization */}
            <div class="relative h-96 bg-gray-50 dark:bg-gray-900">
                <svg class="w-full h-full" viewBox="0 0 800 400">
                    {/* DERP Regions */}
                    <For
                        each=derp_regions
                        key=|region| region.id.clone()
                        children=move |region| {
                            view! {
                                <DerpRegionNode region=region />
                            }
                        }
                    />

                    {/* Connection Lines */}
                    <For
                        each=move || {
                            let nodes_list = nodes.get();
                            let mut connections = Vec::new();

                            // Generate connections between nodes
                            for (i, node1) in nodes_list.iter().enumerate() {
                                for node2 in nodes_list.iter().skip(i + 1) {
                                    if should_draw_connection(node1, node2) {
                                        connections.push((node1.clone(), node2.clone()));
                                    }
                                }
                            }

                            connections
                        }
                        key=|(n1, n2)| format!("{}-{}", n1.id, n2.id)
                        children=move |(node1, node2)| {
                            view! {
                                <ConnectionLine
                                    from=node1
                                    to=node2
                                    selected=move || {
                                        selected_node.get().map_or(false, |id| id == node1.id || id == node2.id)
                                    }
                                />
                            }
                        }
                    />

                    {/* Node Elements */}
                    <For
                        each=nodes
                        key=|node| node.id.clone()
                        children=move |node| {
                            view! {
                                <NetworkNode
                                    node=node.clone()
                                    selected=move || selected_node.get() == Some(node.id.clone())
                                    on_click=move |node_id: String| set_selected_node.set(Some(node_id))
                                />
                            }
                        }
                    />
                </svg>

                {/* Legend */}
                <div class="absolute bottom-4 left-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3 shadow-lg">
                    <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-2">
                        "Legend"
                    </h4>
                    <div class="space-y-2 text-xs">
                        <div class="flex items-center space-x-2">
                            <div class="w-3 h-3 rounded-full bg-green-500"></div>
                            <span class="text-gray-700 dark:text-gray-300">"Online"</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            <div class="w-3 h-3 rounded-full bg-red-500"></div>
                            <span class="text-gray-700 dark:text-gray-300">"Offline"</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            <div class="w-4 h-0.5 bg-blue-500"></div>
                            <span class="text-gray-700 dark:text-gray-300">"Direct"</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            <div class="w-4 h-0.5 bg-orange-500 border-dashed"></div>
                            <span class="text-gray-700 dark:text-gray-300">"DERP"</span>
                        </div>
                    </div>
                </div>

                {/* Selected Node Info */}
                <Show when=move || selected_node.get().is_some()>
                    <div class="absolute top-4 right-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 shadow-lg max-w-sm">
                        {move || {
                            selected_node.get().and_then(|node_id| {
                                nodes.get().into_iter().find(|n| n.id == node_id)
                            }).map(|node| view! {
                                <NodeInfoPanel node=node />
                            })
                        }}
                    </div>
                </Show>
            </div>
        </div>
    }
}

#[component]
fn NetworkNode(
    node: Node,
    #[prop(into)]
    selected: Signal<bool>,
    on_click: Callback<String>,
) -> impl IntoView {
    // Calculate position based on layout mode (simplified)
    let x = (node.id.bytes().sum::<u8>() as f32 % 700.0) + 50.0;
    let y = (node.id.len() as f32 % 300.0) + 50.0;

    let status_color = if node.online { "#10b981" } else { "#ef4444" };
    let stroke_color = move || if selected.get() { "#3b82f6" } else { "#6b7280" };
    let stroke_width = move || if selected.get() { "3" } else { "1" };

    view! {
        <g class="cursor-pointer" on:click=move |_| on_click.call(node.id.clone())>
            {/* Node circle */}
            <circle
                cx=x
                cy=y
                r="12"
                fill=status_color
                stroke=stroke_color
                stroke-width=stroke_width
                class="transition-all duration-200 hover:r-14"
            />

            {/* Node label */}
            <text
                x=x
                y=y + 25
                text-anchor="middle"
                class="text-xs fill-gray-700 dark:fill-gray-300 pointer-events-none"
            >
                {node.name.chars().take(8).collect::<String>()}
            </text>

            {/* OS icon */}
            <text
                x=x
                y=y + 4
                text-anchor="middle"
                class="text-xs fill-white pointer-events-none"
                font-family="monospace"
            >
                {match node.os.as_deref() {
                    Some("linux") => "🐧",
                    Some("windows") => "🪟",
                    Some("darwin") | Some("macos") => "🍎",
                    Some("android") => "🤖",
                    Some("ios") => "📱",
                    _ => "💻",
                }}
            </text>
        </g>
    }
}

#[component]
fn ConnectionLine(
    from: Node,
    to: Node,
    #[prop(into)]
    selected: Signal<bool>,
) -> impl IntoView {
    let from_x = (from.id.bytes().sum::<u8>() as f32 % 700.0) + 50.0;
    let from_y = (from.id.len() as f32 % 300.0) + 50.0;
    let to_x = (to.id.bytes().sum::<u8>() as f32 % 700.0) + 50.0;
    let to_y = (to.id.len() as f32 % 300.0) + 50.0;

    // Determine connection type (direct vs DERP)
    let is_direct = from.online && to.online; // Simplified logic
    let stroke_color = move || if selected.get() { "#3b82f6" } else if is_direct { "#10b981" } else { "#f59e0b" };
    let stroke_dasharray = if is_direct { "none" } else { "5,5" };

    view! {
        <line
            x1=from_x
            y1=from_y
            x2=to_x
            y2=to_y
            stroke=stroke_color
            stroke-width="2"
            stroke-dasharray=stroke_dasharray
            class="transition-all duration-200"
            opacity=move || if selected.get() { "1" } else { "0.6" }
        />
    }
}

#[component]
fn DerpRegionNode(
    region: DerpRegion,
) -> impl IntoView {
    // Position DERP regions around the edges
    let x = match region.id % 4 {
        0 => 100.0,
        1 => 700.0,
        2 => 400.0,
        _ => 400.0,
    };
    let y = match region.id % 4 {
        0 => 100.0,
        1 => 100.0,
        2 => 50.0,
        _ => 350.0,
    };

    view! {
        <g>
            {/* DERP region rectangle */}
            <rect
                x=x - 30
                y=y - 15
                width="60"
                height="30"
                fill="#f3f4f6"
                stroke="#6b7280"
                stroke-width="1"
                rx="4"
                class="dark:fill-gray-700"
            />

            {/* DERP label */}
            <text
                x=x
                y=y + 4
                text-anchor="middle"
                class="text-xs fill-gray-700 dark:fill-gray-300 pointer-events-none"
            >
                {format!("DERP {}", region.id)}
            </text>
        </g>
    }
}

#[component]
fn NodeInfoPanel(
    node: Node,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="flex items-center space-x-2">
                <div class=format!(
                    "w-3 h-3 rounded-full {}",
                    if node.online { "bg-green-500" } else { "bg-red-500" }
                )></div>
                <h4 class="font-medium text-gray-900 dark:text-white">
                    {node.name}
                </h4>
            </div>

            <div class="space-y-2 text-sm">
                <div>
                    <span class="text-gray-600 dark:text-gray-400">"Hostname: "</span>
                    <span class="text-gray-900 dark:text-white">{node.hostname}</span>
                </div>
                <div>
                    <span class="text-gray-600 dark:text-gray-400">"User: "</span>
                    <span class="text-gray-900 dark:text-white">{node.user}</span>
                </div>
                <div>
                    <span class="text-gray-600 dark:text-gray-400">"IPs: "</span>
                    <span class="text-gray-900 dark:text-white font-mono text-xs">
                        {node.ip_addresses.join(", ")}
                    </span>
                </div>
                <div>
                    <span class="text-gray-600 dark:text-gray-400">"OS: "</span>
                    <span class="text-gray-900 dark:text-white">
                        {node.os.unwrap_or_else(|| "Unknown".to_string())}
                    </span>
                </div>
            </div>
        </div>
    }
}

// Helper function to determine if connection should be drawn
fn should_draw_connection(node1: &Node, node2: &Node) -> bool {
    // Simplified logic - in reality this would check routing tables, ACLs, etc.
    node1.online || node2.online
}