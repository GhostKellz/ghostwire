/// Users management page
///
/// Interface for managing users, roles, and permissions in the system.

use leptos::*;

#[component]
pub fn UsersPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "Users"
                </h1>
                <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    "Manage users and their permissions"
                </p>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
                <p class="text-gray-600 dark:text-gray-400">
                    "Users management interface coming soon..."
                </p>
            </div>
        </div>
    }
}