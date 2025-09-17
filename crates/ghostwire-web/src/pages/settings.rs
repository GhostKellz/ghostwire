/// Settings page
///
/// Interface for system configuration and administrative settings.

use leptos::*;

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "Settings"
                </h1>
                <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    "System configuration and administrative settings"
                </p>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
                <p class="text-gray-600 dark:text-gray-400">
                    "Settings interface coming soon..."
                </p>
            </div>
        </div>
    }
}