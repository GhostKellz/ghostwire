/// Card component (stub)

use leptos::*;

#[component]
pub fn Card(children: Children) -> impl IntoView {
    view! {
        <div class="card">
            {children()}
        </div>
    }
}