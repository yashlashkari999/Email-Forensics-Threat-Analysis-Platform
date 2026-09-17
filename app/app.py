import reflex as rx
from app.components.workbench import workbench
from app.states.api import api


def index() -> rx.Component:
    return workbench()


app = rx.App(
    api_transformer=api,
    theme=rx.theme(appearance="light"),
    head_components=[
        rx.el.link(rel="preconnect", href="https://fonts.googleapis.com"),
        rx.el.link(
            rel="preconnect",
            href="https://fonts.gstatic.com",
            cross_origin="",
        ),
        rx.el.link(
            href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Barlow+Condensed:wght@400;500;600;700&display=swap",
            rel="stylesheet",
        ),
    ],
)
app.add_page(
    index,
    route="/",
    title="SIGNAL | Email Forensics Lab",
    description="Evidence-first email analysis, live DNS posture and chain-of-custody reports.",
)
