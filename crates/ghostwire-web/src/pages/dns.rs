/// DNS management page
///
/// Interface for managing MagicDNS records and DNS configuration.

use leptos::*;

#[component]
pub fn DnsPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "DNS"
                </h1>
                <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    "Manage MagicDNS records and DNS configuration"
                </p>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
                <p class="text-gray-600 dark:text-gray-400">
                    "DNS management interface coming soon..."
                </p>
            </div>
        </div>
    }
}