/// Button component (stub)

use leptos::*;

#[component]
pub fn Button(children: Children) -> impl IntoView {
    view! {
        <button class="btn">
            {children()}
        </button>
    }
}