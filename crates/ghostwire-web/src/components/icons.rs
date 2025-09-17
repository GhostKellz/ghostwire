/// Icon components using Lucide icons
///
/// SVG icon components for the GhostWire web interface.

use leptos::*;

#[component]
pub fn GhostWireLogo(
    #[prop(into, optional)]
    class: String,
) -> impl IntoView {
    view! {
        <svg
            class=class
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M12 2L2 7v10c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V7l-10-5z"/>
            <path d="M12 22v-6"/>
            <path d="M8 22v-4"/>
            <path d="M16 22v-4"/>
            <circle cx="12" cy="11" r="2"/>
            <path d="m2 7 4 4 4-2 4 2 4-4"/>
        </svg>
    }
}

#[component]
pub fn ServerIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>
            <rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>
            <line x1="6" x2="6.01" y1="6" y2="6"/>
            <line x1="6" x2="6.01" y1="18" y2="18"/>
        </svg>
    }
}

#[component]
pub fn UsersIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="m22 21-3-3m0 0a2 2 0 0 0 2.8-2.8 2 2 0 0 1-2.8 2.8z"/>
        </svg>
    }
}

#[component]
pub fn UserIcon(
    #[prop(into, optional)]
    class: String,
) -> impl IntoView {
    view! {
        <svg
            class=class
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
        </svg>
    }
}

#[component]
pub fn LockIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
            <path d="m7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
    }
}

#[component]
pub fn GlobeIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <circle cx="12" cy="12" r="10"/>
            <path d="m12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            <path d="M2 12h20"/>
        </svg>
    }
}

#[component]
pub fn SettingsIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
            <circle cx="12" cy="12" r="3"/>
        </svg>
    }
}

#[component]
pub fn DashboardIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <rect width="7" height="9" x="3" y="3" rx="1"/>
            <rect width="7" height="5" x="14" y="3" rx="1"/>
            <rect width="7" height="9" x="14" y="12" rx="1"/>
            <rect width="7" height="5" x="3" y="16" rx="1"/>
        </svg>
    }
}

#[component]
pub fn NetworkIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <circle cx="12" cy="12" r="2"/>
            <path d="M12 1v6m0 6v6"/>
            <path d="m15.5 3.5-1.5 1.5m-2 2-1.5 1.5"/>
            <path d="m20.5 8.5-1.5 1.5m-2 2-1.5 1.5"/>
            <path d="m20.5 15.5-1.5-1.5m-2-2-1.5-1.5"/>
            <path d="m15.5 20.5-1.5-1.5m-2-2-1.5-1.5"/>
            <path d="m8.5 20.5 1.5-1.5m2-2 1.5-1.5"/>
            <path d="m3.5 15.5 1.5-1.5m2-2 1.5-1.5"/>
            <path d="m3.5 8.5 1.5 1.5m2 2 1.5 1.5"/>
            <path d="m8.5 3.5 1.5 1.5m2 2 1.5 1.5"/>
        </svg>
    }
}

#[component]
pub fn MenuIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <line x1="4" x2="20" y1="6" y2="6"/>
            <line x1="4" x2="20" y1="12" y2="12"/>
            <line x1="4" x2="20" y1="18" y2="18"/>
        </svg>
    }
}

#[component]
pub fn CloseIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="m18 6-12 12"/>
            <path d="m6 6 12 12"/>
        </svg>
    }
}

#[component]
pub fn CheckIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="m9 12 2 2 4-4"/>
            <circle cx="12" cy="12" r="10"/>
        </svg>
    }
}

#[component]
pub fn AlertIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/>
            <path d="M12 9v4"/>
            <path d="m12 17.02.01 0"/>
        </svg>
    }
}

#[component]
pub fn InfoIcon() -> impl IntoView {
    view! {
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <circle cx="12" cy="12" r="10"/>
            <path d="m9 9h.01"/>
            <path d="m9 12h6v3"/>
        </svg>
    }
}

#[component]
pub fn LoadingIcon() -> impl IntoView {
    view! {
        <svg
            class="animate-spin"
            viewBox="0 0 24 24"
            fill="none"
        >
            <circle
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                stroke-width="4"
                class="opacity-25"
            />
            <path
                fill="currentColor"
                d="m4 12a8 8 0 0 1 8-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 0 1 4 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                class="opacity-75"
            />
        </svg>
    }
}