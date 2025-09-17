/// Shell component that wraps the main application layout
///
/// Provides the overall structure with header, sidebar navigation, main content area, and footer.

use leptos::*;
use leptos_router::*;

use crate::auth::use_auth;
use crate::components::{header::Header, footer::Footer, sidebar::Sidebar};

#[component]
pub fn Shell(children: Children) -> impl IntoView {
    let auth = use_auth();

    // Get the current session to pass to components
    let session = move || auth.session.get();

    view! {
        <div class="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
            <Header session=session />

            <div class="flex flex-1">
                <Sidebar session=session />

                <main class="flex-1 overflow-hidden">
                    <div class="h-full overflow-y-auto">
                        <div class="container mx-auto px-4 py-6 max-w-7xl">
                            {children()}
                        </div>
                    </div>
                </main>
            </div>

            <Footer/>
        </div>
    }
}