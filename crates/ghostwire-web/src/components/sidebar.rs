/// Sidebar navigation component
///
/// Left navigation sidebar with collapsible menu items and active state indicators.

use leptos::*;

use crate::types::AuthSession;

#[component]
pub fn Sidebar(
    #[prop(into)]
    session: Signal<Option<AuthSession>>,
) -> impl IntoView {
    // For now, we'll use a simple sidebar placeholder
    // In a full implementation, this would have collapsible sections
    // and proper responsive behavior

    view! {
        <aside class="hidden lg:block w-64 bg-gray-50 dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800">
            <div class="h-full px-4 py-6">
                <div class="text-center text-gray-500 dark:text-gray-400 text-sm">
                    "Sidebar navigation coming soon..."
                </div>
            </div>
        </aside>
    }
}