import dash_bootstrap_components as dbc
from dash import html

def create_navbar(username):
    return dbc.Navbar(
        [
            dbc.NavbarBrand(
                html.Span([
                     html.I(className="fas fa-tachometer-alt me-2"),  # icon dashboard
                     "5G Network Monitor"
                ]),
                href="/",
                className="navbar-brand-custom ms-2 fs-3 fw-semibold"
            ),
            dbc.Nav(
                [
                    dbc.NavItem(dbc.NavLink("WORKPLACE", href="/dashboard", active="exact", className="nav-link-custom text-light fs-5")),
                    dbc.NavItem(dbc.NavLink("ABOUT", href="/about", active="exact", className="nav-link-custom fs-5")),
                ],
                className="mx-auto",
                navbar=True,

            ),
            dbc.Nav(
                [
                    html.Span(f"Welcome, {username} !", style={"color": "white", "margin-right": "10px","margin-top": "10px", "font-size": "20px"}),
                    dbc.Button(
                        "LOG OUT",
                        id="logout-button",  
                        n_clicks=0,        
                        className="me-2",
                        style={
                            "height": "3rem",
                            "width": "auto"
                        }
                    )
                ],
                className="ml-auto",
                navbar=True
            ),
        ],
        color="#1C3782",
        className="mb-4",
        style={
            "height": "60px",
            "width": "100%",
            "position": "fixed",
            "top": "0",
            "left": "0",
            "z-index": "1000"
        }
    )