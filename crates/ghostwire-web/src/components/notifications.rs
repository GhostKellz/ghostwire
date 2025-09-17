/// Notification system for user feedback
///
/// Toast notifications and alert system for showing success, error, warning, and info messages.

use leptos::*;
use std::collections::HashMap;
use uuid::Uuid;

use crate::types::{Notification, NotificationType};
use crate::components::icons::*;

/// Notification context for managing toast notifications
#[derive(Debug, Clone)]
pub struct NotificationContext {
    pub notifications: ReadSignal<Vec<Notification>>,
    pub add_notification: WriteSignal<Vec<Notification>>,
    pub show_success: Callback<(String, Option<String>)>,
    pub show_error: Callback<(String, Option<String>)>,
    pub show_warning: Callback<(String, Option<String>)>,
    pub show_info: Callback<(String, Option<String>)>,
    pub remove_notification: Callback<Uuid>,
}

/// Notification provider component
#[component]
pub fn NotificationProvider(children: Children) -> impl IntoView {
    let (notifications, set_notifications) = create_signal::<Vec<Notification>>(Vec::new());

    let add_notification = move |notification: Notification| {
        set_notifications.update(|notifications| {
            notifications.push(notification.clone());

            // Auto-remove after duration if specified
            if notification.auto_dismiss {
                let duration = notification.duration.unwrap_or(5);
                let id = notification.id;

                gloo_timers::callback::Timeout::new(duration * 1000, move || {
                    set_notifications.update(|notifications| {
                        notifications.retain(|n| n.id != id);
                    });
                }).forget();
            }
        });
    };

    let remove_notification = move |id: Uuid| {
        set_notifications.update(|notifications| {
            notifications.retain(|n| n.id != id);
        });
    };

    let show_success = move |(title, message): (String, Option<String>)| {
        let notification = Notification {
            id: Uuid::new_v4(),
            notification_type: NotificationType::Success,
            title,
            message,
            auto_dismiss: true,
            duration: Some(5),
        };
        add_notification(notification);
    };

    let show_error = move |(title, message): (String, Option<String>)| {
        let notification = Notification {
            id: Uuid::new_v4(),
            notification_type: NotificationType::Error,
            title,
            message,
            auto_dismiss: false,
            duration: None,
        };
        add_notification(notification);
    };

    let show_warning = move |(title, message): (String, Option<String>)| {
        let notification = Notification {
            id: Uuid::new_v4(),
            notification_type: NotificationType::Warning,
            title,
            message,
            auto_dismiss: true,
            duration: Some(8),
        };
        add_notification(notification);
    };

    let show_info = move |(title, message): (String, Option<String>)| {
        let notification = Notification {
            id: Uuid::new_v4(),
            notification_type: NotificationType::Info,
            title,
            message,
            auto_dismiss: true,
            duration: Some(5),
        };
        add_notification(notification);
    };

    let context = NotificationContext {
        notifications,
        add_notification: set_notifications,
        show_success: Callback::new(show_success),
        show_error: Callback::new(show_error),
        show_warning: Callback::new(show_warning),
        show_info: Callback::new(show_info),
        remove_notification: Callback::new(remove_notification),
    };

    provide_context(context);

    view! {
        {children()}
        <NotificationContainer/>
    }
}

/// Hook to access notification context
pub fn use_notifications() -> NotificationContext {
    use_context::<NotificationContext>()
        .expect("NotificationContext must be provided by NotificationProvider")
}

/// Container that renders all active notifications
#[component]
fn NotificationContainer() -> impl IntoView {
    let notifications = use_notifications();

    view! {
        <div class="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
            <For
                each=move || notifications.notifications.get()
                key=|notification| notification.id
                children=move |notification| {
                    view! { <NotificationToast notification=notification /> }
                }
            />
        </div>
    }
}

/// Individual notification toast component
#[component]
fn NotificationToast(notification: Notification) -> impl IntoView {
    let notifications = use_notifications();

    let (bg_class, border_class, text_class, icon) = match notification.notification_type {
        NotificationType::Success => (
            "bg-green-50 dark:bg-green-900/20",
            "border-green-200 dark:border-green-800",
            "text-green-800 dark:text-green-400",
            view! { <CheckIcon/> }.into_view(),
        ),
        NotificationType::Error => (
            "bg-red-50 dark:bg-red-900/20",
            "border-red-200 dark:border-red-800",
            "text-red-800 dark:text-red-400",
            view! { <AlertIcon/> }.into_view(),
        ),
        NotificationType::Warning => (
            "bg-yellow-50 dark:bg-yellow-900/20",
            "border-yellow-200 dark:border-yellow-800",
            "text-yellow-800 dark:text-yellow-400",
            view! { <AlertIcon/> }.into_view(),
        ),
        NotificationType::Info => (
            "bg-blue-50 dark:bg-blue-900/20",
            "border-blue-200 dark:border-blue-800",
            "text-blue-800 dark:text-blue-400",
            view! { <InfoIcon/> }.into_view(),
        ),
    };

    let notification_id = notification.id;

    view! {
        <div class=format!(
            "rounded-lg border p-4 shadow-lg transition-all duration-300 {} {}",
            bg_class, border_class
        )>
            <div class="flex">
                <div class=format!("flex-shrink-0 w-5 h-5 {}", text_class)>
                    {icon}
                </div>
                <div class="ml-3 flex-1">
                    <h3 class=format!("text-sm font-medium {}", text_class)>
                        {notification.title.clone()}
                    </h3>
                    <Show when=move || notification.message.is_some()>
                        <div class=format!("mt-1 text-sm {}", text_class)>
                            {notification.message.clone().unwrap_or_default()}
                        </div>
                    </Show>
                </div>
                <div class="ml-4 flex-shrink-0">
                    <button
                        class=format!(
                            "inline-flex rounded-md p-1.5 hover:bg-opacity-20 focus:outline-none focus:ring-2 focus:ring-offset-2 {}",
                            text_class
                        )
                        on:click=move |_| {
                            notifications.remove_notification.call(notification_id);
                        }
                    >
                        <span class="sr-only">"Dismiss"</span>
                        <CloseIcon/>
                    </button>
                </div>
            </div>
        </div>
    }
}