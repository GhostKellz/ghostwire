/// Footer component
///
/// Application footer with version info and links.

use leptos::*;

#[component]
pub fn Footer() -> impl IntoView {
    view! {
        <footer class="bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800 py-4">
            <div class="container mx-auto px-4">
                <div class="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                    <div>
                        "GhostWire v0.1.0"
                    </div>
                    <div class="flex space-x-4">
                        <a
                            href="https://github.com/ghostkellz/ghostwire"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="hover:text-gray-900 dark:hover:text-white transition-colors"
                        >
                            "GitHub"
                        </a>
                        <a
                            href="/docs"
                            class="hover:text-gray-900 dark:hover:text-white transition-colors"
                        >
                            "Documentation"
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    }
}