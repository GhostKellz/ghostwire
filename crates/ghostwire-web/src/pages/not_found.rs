/// 404 Not Found page
///
/// Error page for routes that don't exist.

use leptos::*;
use leptos_router::*;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="min-h-[60vh] flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-900 dark:text-white">
                    "404"
                </h1>
                <p class="mt-4 text-xl text-gray-600 dark:text-gray-400">
                    "Page not found"
                </p>
                <p class="mt-2 text-gray-500 dark:text-gray-500">
                    "The page you're looking for doesn't exist."
                </p>
                <div class="mt-8">
                    <A
                        href="/dashboard"
                        class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    >
                        "Go to Dashboard"
                    </A>
                </div>
            </div>
        </div>
    }
}